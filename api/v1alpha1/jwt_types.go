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

// +genclient

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// JwtSpec defines the desired state of Jwt
type JwtSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	//Subject set in token
	Subject string `json:"subject"`

	RotatingKeyRef RotatingKeyRef `json:"rotatingKeyRef"`
}

type RotatingKeyRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// JwtStatus defines the observed state of Jwt
type JwtStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	//Token lifetime
	Algorithm          string       `json:"algorithm"`
	Lifetime           string       `json:"lifetime"`
	Expired            bool         `json:"expired"`
	ExpiresAt          metav1.Time  `json:"expiresAt"`
	RefreshAfter       metav1.Time  `json:"refreshAfter"`
	LastRefresh        *metav1.Time `json:"lastRefresh,omitempty"`
	NextReconcile      metav1.Time  `json:"nextReconcile,omitempty"`
	LastTransitionTime metav1.Time  `json:"lastTransitionTime"`
	Ready              bool         `json:"ready"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Jwt is the Schema for the jwts API
type Jwt struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   JwtSpec   `json:"spec,omitempty"`
	Status JwtStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// JwtList contains a list of Jwt
type JwtList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Jwt `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Jwt{}, &JwtList{})
}
