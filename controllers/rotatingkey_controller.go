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

package controllers

import (
	"context"
	"github.com/hexhibit/tokator/crypto"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tokensv1alpha1 "github.com/hexhibit/tokator/api/v1alpha1"
)

// RotatingKeyReconciler reconciles a RotatingKey object
type RotatingKeyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=tokens.hexhibit.xyz,resources=rotatingkeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tokens.hexhibit.xyz,resources=rotatingkeys/status,verbs=get;update;patch

func (r *RotatingKeyReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := Logger{r.Log.WithValues("rotatingkey", req.NamespacedName)}

	rotatingKey := &tokensv1alpha1.RotatingKey{}
	err := r.Client.Get(ctx, req.NamespacedName, rotatingKey)
	if err != nil {
		if errors.IsNotFound(err) {
			//Requested Object not found
			return log.errResult(err, "requested object not found, might be deleted")
		}
		return log.errResult(err, "")
	}

	publicKey := ""
	secret := &v1.Secret{}

	err = r.Client.Get(ctx, types.NamespacedName{Name: rotatingKey.Name, Namespace: rotatingKey.Namespace}, secret)
	if err != nil && errors.IsNotFound(err) {

		log.Info("keys not found, create new")

		private, public, err := crypto.CreateKeys()
		if err != nil {
			return log.errResult(err, "failed to create keys")
		}

		secret = crypto.DecodedToSecret(private)

		if err != nil {
			return log.errResult(err, "failed to generate secret")
		}

		err = r.Client.Create(context.Background(), secret, &client.CreateOptions{})
		if err != nil {
			return log.errResult(err, "failed to create secret")
		}

		publicKey = public

	} else if err != nil {
		return log.errResult(err, "failed to get secret")
	}

	if rotatingKey.Status.SigningKey.PublicKey != publicKey {
		//TODO
	}

	nextRoation := rotatingKey.Status.NexRotation.Time
	if metav1.Now().After(nextRoation) {
		//rotate
	}

	// your logic here

	return ctrl.Result{}, nil
}

func (r *RotatingKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&tokensv1alpha1.RotatingKey{}).
		Complete(r)
}

func generateKeySecret() {

}
