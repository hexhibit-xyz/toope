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
	"github.com/go-logr/logr"
	tokensv1alpha1 "github.com/hexhibit-xyz/toope/api/v1alpha1"
	"github.com/hexhibit-xyz/toope/crypto"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	rand2 "k8s.io/apimachinery/pkg/util/rand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"time"
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

	secret := &v1.Secret{}

	// Try to fetch the secret
	// containing the private signing key
	err = r.Client.Get(ctx, types.NamespacedName{Name: rotatingKey.Name, Namespace: rotatingKey.Namespace}, secret)
	//If not found, create new keys
	if err != nil && errors.IsNotFound(err) {

		log.Info("keys not found, create new")

		private, public, err := crypto.CreateKeys()
		if err != nil {
			return log.errResult(err, "failed to create keys")
		}

		//Decode the private key and create a new secret
		secret = &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rotatingKey.Name,
				Namespace: rotatingKey.Namespace,
			},
			Type: "Opaque",
		}
		crypto.DecodedToSecret(private, secret)
		err = r.Client.Create(context.Background(), secret, &client.CreateOptions{})
		if err != nil {
			return log.errResult(err, "failed to create secret")
		}

		//Set new created public key as new verification key
		rotatingKey.Status.SigningKey.PublicKey = public
		rotatingKey.Status.SigningKey.KeyID = rand2.String(20)
		rotate, err := time.ParseDuration(rotatingKey.Spec.RotateAfter)
		if err != nil {
			return log.errResult(err, "unsupported duration format")
		}
		rotatingKey.Status.NexRotation.Time = time.Now().Add(rotate)

	} else if err != nil {
		return log.errResult(err, "failed to get secret")
	}

	//Create key set from status
	cryptoKeys, err := StatusToKeys(rotatingKey, secret)
	if err != nil {
		return log.errResult(err, "failed to convert to crypto keys")
	}

	nextRoation := rotatingKey.Status.NexRotation.Time
	if metav1.Now().After(nextRoation) {
		strategy, err := crypto.NewRotationStrategy(rotatingKey.Spec.Algorithm, rotatingKey.Spec.RotateAfter, rotatingKey.Spec.Lifetime)
		if err != nil {
			return log.errResult(err, "failed to create strategy")
		}

		rotator := crypto.NewRotater(strategy)
		err = rotator.Rotate(&cryptoKeys)
		if err != nil {
			return log.errResult(err, "failed to rotate")
		}

		crypto.ToSecret(cryptoKeys.SigningKey, secret)
		err = r.Update(ctx, secret)
		if err != nil {
			return log.errResult(err, "failed to update secret with new private key")
		}
	}

	rotatingKey.Status = KeysToStatus(cryptoKeys)

	err = r.Status().Update(ctx, rotatingKey)
	if err != nil {
		return log.errResult(err, "failed to update rotating key status")
	}

	err = controllerutil.SetControllerReference(rotatingKey, secret, r.Scheme)
	if err != nil {
		return log.errResult(err, "failed to set token controller reference")
	}

	next := rotatingKey.Status.NexRotation.Sub(time.Now()) + 1*time.Minute

	return ctrl.Result{RequeueAfter: next}, nil
}

func (r *RotatingKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&tokensv1alpha1.RotatingKey{}).
		Owns(&v1.Secret{}).
		Complete(r)
}

func StatusToKeys(key *tokensv1alpha1.RotatingKey, secret *v1.Secret) (crypto.Keys, error) {
	vks := key.Status.VerificationKeys

	privateKey, err := crypto.FromSecret(secret)
	if err != nil {
		return crypto.Keys{}, err
	}

	keys := make([]crypto.VerificationKey, len(vks))
	for i, k := range vks {

		pub, err := crypto.EncodePublicRSA(k.PublicKey)
		if err != nil {
			return crypto.Keys{}, err
		}

		keys[i] = crypto.VerificationKey{
			PublicKey: *pub,
			Expiry:    k.ExpireAt.Time,
			Kid:       k.KeyID,
		}
	}

	return crypto.Keys{
		SigningKey:       privateKey,
		VerificationKeys: keys,
		NextRotation:     key.Status.NexRotation.Time,
		SigningKid:       key.Status.SigningKey.KeyID,
	}, nil

}

func KeysToStatus(keys crypto.Keys) tokensv1alpha1.RotatingKeyStatus {
	valK := make([]tokensv1alpha1.ValidationKey, len(keys.VerificationKeys))

	for i, k := range keys.VerificationKeys {
		valK[i] = tokensv1alpha1.ValidationKey{
			KeyID:     k.Kid,
			Use:       "enc",
			PublicKey: crypto.DecodeRSAPublic(k.PublicKey),
			ExpireAt:  metav1.NewTime(k.Expiry),
		}
	}

	return tokensv1alpha1.RotatingKeyStatus{
		NexRotation:      metav1.NewTime(keys.NextRotation),
		VerificationKeys: valK,
		SigningKey: tokensv1alpha1.SigningKey{
			KeyID:     keys.SigningKid,
			Use:       "sig",
			PublicKey: crypto.DecodeRSAPublic(keys.SigningKey.PublicKey),
		},
	}
}
