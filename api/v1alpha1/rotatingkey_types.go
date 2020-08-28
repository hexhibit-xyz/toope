/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// RotatingKeySpec defines the desired state of RotatingKey
type RotatingKeySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of RotatingKey. Edit RotatingKey_types.go to remove/update
	Algorithm   string `json:"algorithm"`
	RotateAfter string `json:"rotateAfter"`
}

// RotatingKeyStatus defines the observed state of RotatingKey
type RotatingKeyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	NexRotation    metav1.Time     `json:"nextRotation"`
	ValidationKeys []ValidationKey `json:"validationKeys"`
	SigningKey     SigningKey      `json:"signingKeys"`
}

type ValidationKey struct {
	KeyID     string      `json:"keyID"`
	Use       string      `json:"use"`
	PublicKey string      `json:"publicKey"`
	ExpireAt  metav1.Time `json:"expire"`
}

type SigningKey struct {
	KeyID      string `json:"keyID"`
	Use        string `json:"use"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// RotatingKey is the Schema for the rotatingkeys API
type RotatingKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RotatingKeySpec   `json:"spec,omitempty"`
	Status RotatingKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RotatingKeyList contains a list of RotatingKey
type RotatingKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RotatingKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RotatingKey{}, &RotatingKeyList{})
}
