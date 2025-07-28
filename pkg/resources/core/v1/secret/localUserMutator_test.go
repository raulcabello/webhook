package secret

import (
	"encoding/json"
	"fmt"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	ctrlv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	authenicationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"testing"
)

func TestLocalUserMutatorAdmit(t *testing.T) {
	ctrl := gomock.NewController(t)
	patchType := admissionv1.PatchTypeJSONPatch
	rawSecret, err := json.Marshal(&v1.Secret{
		Data: map[string][]byte{
			"password": []byte("password"),
		},
	})
	assert.NoError(t, err)
	rawHashedSecret, err := json.Marshal(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				passwordHashAnnotation: pbkdf2sha3512Hash,
			},
		},
		Data: map[string][]byte{
			"password": []byte("password"),
		},
	})
	assert.NoError(t, err)

	tests := map[string]struct {
		request           *admission.Request
		hasher            passwordHasher
		mockSettingsCache func() ctrlv3.SettingCache
		wantResponse      *admissionv1.AdmissionResponse
		wantErr           string
	}{
		"password is successfully hashed": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user"},
					Object: runtime.RawExtension{
						Raw: rawSecret,
					},
				},
			},
			hasher: func(password string) ([]byte, []byte, error) {
				return []byte("hashedPassword"), []byte("salt"), nil
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
				mock.EXPECT().Get(passwordMinLengthSetting).Return(&v3.Setting{
					Value: "5",
				}, nil)

				return mock
			},
			wantResponse: &admissionv1.AdmissionResponse{
				Allowed:   true,
				Patch:     []byte(`[{"op":"add","path":"/metadata/annotations","value":{"cattle.io/password-hash":"pbkdf2sha3512"}},{"op":"replace","path":"/data/password","value":"aGFzaGVkUGFzc3dvcmQ="},{"op":"add","path":"/data/salt","value":"c2FsdA=="}]`), // aGFzaGVkUGFzc3dvcmQ= -> hashedPassword base64 encoded, and c2FsdA==" => salt base64 encoded
				PatchType: &patchType,
			},
		},
		"password was already hashed": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user"},
					Object: runtime.RawExtension{
						Raw: rawHashedSecret,
					},
				},
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
			},
			wantResponse: &admissionv1.AdmissionResponse{
				Allowed: true,
			},
		},
		"password is shorter than password-min-length setting": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user"},
					Object: runtime.RawExtension{
						Raw: rawSecret,
					},
				},
			},
			hasher: func(password string) ([]byte, []byte, error) {
				return []byte("hashedPassword"), []byte("salt"), nil
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
				mock.EXPECT().Get(passwordMinLengthSetting).Return(&v3.Setting{
					Value: "10",
				}, nil)

				return mock
			},
			wantResponse: &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  "Failure",
					Code:    400,
					Reason:  "BadRequest",
					Message: "password must be at least 10 characters",
				},
			},
		},
		"password is the same as the user name": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "password"},
					Object: runtime.RawExtension{
						Raw: rawSecret,
					},
				},
			},
			hasher: func(password string) ([]byte, []byte, error) {
				return []byte("hashedPassword"), []byte("salt"), nil
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
				mock.EXPECT().Get(passwordMinLengthSetting).Return(&v3.Setting{
					Value: "10",
				}, nil)

				return mock
			},
			wantResponse: &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  "Failure",
					Code:    400,
					Reason:  "BadRequest",
					Message: "password must be at least 10 characters",
				},
			},
		},
		"error creating hashed password": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object: runtime.RawExtension{
						Raw: rawSecret,
					},
				},
			},
			hasher: func(password string) ([]byte, []byte, error) {
				return nil, nil, fmt.Errorf("unexpected error")
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
				mock.EXPECT().Get(passwordMinLengthSetting).Return(&v3.Setting{
					Value: "5",
				}, nil)

				return mock
			},
			wantErr: "unexpected error",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := LocalUserMutator{
				hasher:       test.hasher,
				settingCache: test.mockSettingsCache(),
			}

			response, err := m.Admit(test.request)

			assert.Equal(t, test.wantResponse, response)

			if test.wantErr != "" {
				assert.EqualError(t, err, test.wantErr)
			}
		})
	}
}
