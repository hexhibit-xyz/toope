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
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"time"

	tokensv1alpha1 "github.com/hexhibit/tokator/api/v1alpha1"
)

var defaultLabels = map[string]string{
	"tokator.hexhibit.xyz/controlled": "true"}

// JwtReconciler reconciles a Jwt object
type JwtReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

type Logger struct {
	logr.Logger
}

func (l Logger) errResult(err error, msg string) (ctrl.Result, error) {
	l.Error(err, msg)
	return ctrl.Result{}, err
}

// +kubebuilder:rbac:groups=tokens.hexhibit.xyz,resources=jwts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tokens.hexhibit.xyz,resources=jwts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;update;patch;watch;list;delete;create

func (r *JwtReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {

	log := Logger{r.Log.WithValues("jwt", req.NamespacedName)}
	log.Info("reconcile: " + req.String())

	ctx := context.Background()

	token := &tokensv1alpha1.Jwt{}
	err := r.Client.Get(ctx, req.NamespacedName, token)
	if err != nil {
		if errors.IsNotFound(err) {
			//Requested Object not found
			return log.errResult(err, "requested object not found, might be deleted")
		}
		return log.errResult(err, "")
	}

	secret := &v1.Secret{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: token.Name, Namespace: token.Namespace}, secret)
	if err != nil && errors.IsNotFound(err) {

		secret, err = generateSecret(*token)
		if err != nil {
			return log.errResult(err, "failed to generate secret")
		}

		err = r.Client.Create(context.Background(), secret, &client.CreateOptions{})
		if err != nil {
			return log.errResult(err, "failed to create secret")
		}

	} else if err != nil {
		return log.errResult(err, "failed to get secret")
	}

	now := metav1.Now()
	if token.Status.Expired || token.Status.ExpiresAt.Before(&now) || token.Status.RefreshAfter.Before(&now) {
		log.Info("token is expired, try to refresh")
		updateSecret(*token, secret)

		log.Info("update secret")
		err = r.Client.Update(context.TODO(), secret, &client.UpdateOptions{})
		if err != nil {
			return log.errResult(err, "failed to update secret")
		}

	}

	updateRefreshStatus(token)

	log.Info("update token")
	err = r.Status().Update(ctx, token)
	if err != nil {
		return log.errResult(err, "failed to update token")
	}

	err = controllerutil.SetControllerReference(token, secret, r.Scheme)
	if err != nil {
		return log.errResult(err, "failed to set token controller reference")
	}

	return ctrl.Result{RequeueAfter: token.Status.NextReconcile.Sub(time.Now())}, nil
}

func updateRefreshStatus(token *tokensv1alpha1.Jwt) {

	now := metav1.Now()
	creationDate := now
	if token.Status.LastRefresh != nil {
		creationDate = *token.Status.LastRefresh
	}

	lifetime, err := time.ParseDuration(token.Spec.Lifetime)
	if err != nil {
		lifetime = 10 * time.Minute
	}

	expAt := creationDate.Add(lifetime)
	refAfter := creationDate.Add(lifetime * 7 / 10.0)
	nextReconcile := creationDate.Add(lifetime * 8 / 10.0)

	token.Status = tokensv1alpha1.JwtStatus{
		Expired:            false,
		ExpiresAt:          metav1.NewTime(expAt),
		RefreshAfter:       metav1.NewTime(refAfter),
		NextReconcile:      metav1.NewTime(nextReconcile),
		LastTransitionTime: now,
		Ready:              true,
	}
}

func generateSecret(jwt tokensv1alpha1.Jwt) (secret *v1.Secret, err error) {

	alog := jwt.Spec.Algorithm
	if alog == "" {
		return secret, fmt.Errorf("no signing algorithm set")
	}

	a := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, jwtgo.MapClaims{})

	token, err := a.SignedString([]byte("secret"))
	if err != nil {
		return secret, err
	}

	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jwt.Name,
			Namespace: jwt.Namespace,
			Labels:    defaultLabels,
		},
		Immutable:  nil,
		Data:       nil,
		StringData: map[string]string{"token": token},
		Type:       "Opaque",
	}, nil
}

func updateSecret(jwt tokensv1alpha1.Jwt, secret *v1.Secret) {
	a := jwtgo.New(jwtgo.SigningMethodES256)
	token, _ := a.SignedString([]byte("YOLOLOLO"))
	secret.StringData = map[string]string{"token": token}
}

func (r *JwtReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&tokensv1alpha1.Jwt{}).
		Owns(&v1.Secret{}).
		Complete(r)
}
