package secret

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	"github.com/rancher/webhook/pkg/patch"
	"strconv"
	"unicode/utf8"

	"github.com/rancher/webhook/pkg/admission"
	ctrlv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

const (
	localUserPasswordsNamespace = "cattle-local-user-passwords"
	passwordHashAnnotation      = "cattle.io/password-hash"
	pbkdf2sha3512Hash           = "pbkdf2sha3512"
	iterations                  = 210000
	keyLength                   = 32
	passwordMinLengthSetting    = "password-min-length"
)

type passwordHasher func(password string) ([]byte, []byte, error)

// LocalUserMutator implements admission.MutatingAdmissionWebhook.
type LocalUserMutator struct {
	hasher       passwordHasher
	settingCache ctrlv3.SettingCache
}

// NewLocalUserMutator returns a new mutator which mutates secret objects, and related resources
func NewLocalUserMutator(settingCache ctrlv3.SettingCache) *LocalUserMutator {
	return &LocalUserMutator{
		settingCache: settingCache,
		hasher:       hashPassword,
	}
}

// GVR returns the GroupVersionKind for this CRD.
func (m *LocalUserMutator) GVR() schema.GroupVersionResource {
	return corev1.SchemeGroupVersion.WithResource("secrets")
}

// Operations returns list of operations handled by this mutator.
func (m *LocalUserMutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *LocalUserMutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.NamespacedScope, m.Operations())
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	mutatingWebhook.TimeoutSeconds = admission.Ptr(int32(15))
	mutatingWebhook.NamespaceSelector = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      corev1.LabelMetadataName,
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{localUserPasswordsNamespace},
			},
		},
	}

	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit is the entrypoint for the mutator. Admit will return an error if it unable to process the request.
func (m *LocalUserMutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.DryRun != nil && *request.DryRun {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}
	listTrace := trace.New("local user password secret Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	secret, err := objectsv1.SecretFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}
	if secret.Annotations[passwordHashAnnotation] == pbkdf2sha3512Hash {
		// password is already encrypted
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}
	password := string(secret.Data["password"])
	passwordMinLength, err := m.getPasswordMinLength()
	if err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(password) < passwordMinLength {
		return admission.ResponseBadRequest(fmt.Sprintf("password must be at least %v characters", passwordMinLength)), nil
	}
	if request.UserInfo.Username == password {
		return admission.ResponseBadRequest("password cannot be the same as username"), nil
	}
	hashedPassword, salt, err := m.hasher(password)
	if err != nil {
		return nil, err
	}
	response := &admissionv1.AdmissionResponse{}
	newSecret := secret.DeepCopy()
	if newSecret.Annotations == nil {
		newSecret.Annotations = map[string]string{}
	}
	newSecret.Annotations[passwordHashAnnotation] = pbkdf2sha3512Hash
	newSecret.Data["password"] = hashedPassword
	newSecret.Data["salt"] = salt
	if err := patch.CreatePatch(request.Object.Raw, newSecret, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true

	return response, nil
}

func (m *LocalUserMutator) getPasswordMinLength() (int, error) {
	setting, err := m.settingCache.Get("password-min-length")
	if err != nil {
		return 0, err
	}
	var passwordMinLength int
	if setting.Value != "" {
		passwordMinLength, err = strconv.Atoi(setting.Value)
		if err != nil {
			return 0, err
		}
	} else {
		passwordMinLength, err = strconv.Atoi(setting.Default)
		if err != nil {
			return 0, err
		}
	}

	return passwordMinLength, nil
}

func hashPassword(password string) ([]byte, []byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	passwordHashed, err := pbkdf2.Key(sha3.New512, password, salt, iterations, keyLength)
	if err != nil {
		return nil, nil, err
	}

	return passwordHashed, salt, nil
}
