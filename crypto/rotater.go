package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/sirupsen/logrus"
	"time"
)

// Keys hold encryption and signing keys.
type Keys struct {
	// Key for creating and verifying signatures. These may be nil.
	SigningKey *rsa.PrivateKey

	// Old signing keys which have been rotated but can still be used to validate
	// existing signatures.
	VerificationKeys []VerificationKey

	// The next time the signing keyGenFunc will rotate.
	//
	// For caching purposes, implementations MUST NOT update keys before this time.
	NextRotation time.Time
}

// VerificationKey is a rotated signing keyGenFunc which can still be used to verify
// signatures.
type VerificationKey struct {
	PublicKey rsa.PublicKey
	Expiry    time.Time
}

type keyRotater struct {
	strategy rotationStrategy
	logger   *logrus.Logger
}

// rotationStrategy describes a strategy for generating cryptographic keys, how
// often to rotate them, and how long they can validate signatures after rotation.
type rotationStrategy struct {
	// Time between rotations.
	rotationFrequency time.Duration

	// After being rotated how long should the keyGenFunc be kept around for validating
	// signatues?
	idTokenValidFor time.Duration

	algorithm string
}

type AsymmetricAlg interface {
	Public() AsymmetricAlg
}

func NewRotationStrategy(algorithm string, rotationFrequency, idTokenValidFor time.Duration) (rotationStrategy, error) {
	return rotationStrategy{
		rotationFrequency: rotationFrequency,
		idTokenValidFor:   idTokenValidFor,
		algorithm:         algorithm,
	}, nil
}

func NewRotater(strategy rotationStrategy) keyRotater {
	return keyRotater{
		strategy: strategy,
		logger:   logrus.New(),
	}
}

func (k keyRotater) rotate(keys *Keys) error {
	k.logger.Infof("keys expired, rotating")

	// Generate the keyGenFunc outside of a storage transaction.
	key, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return fmt.Errorf("generate keyGenFunc: %v", err)
	}

	var nextRotation time.Time
	tNow := time.Now()

	// if you are running multiple instances of dex, another instance
	// could have already rotated the keys.
	if tNow.Before(keys.NextRotation) {
		k.logger.Error("FUCK WHAT NOW?")
	}

	expired := func(key VerificationKey) bool {
		return tNow.After(key.Expiry)
	}
	// Remove any verification keys that have expired.
	i := 0
	for _, key := range keys.VerificationKeys {
		if !expired(key) {
			keys.VerificationKeys[i] = key
			i++
		}
	}
	keys.VerificationKeys = keys.VerificationKeys[:i]

	if keys.SigningKey.PublicKey.Size() > 0 {
		// Move current signing keyGenFunc to a verification only keyGenFunc, throwing
		// away the private part.
		verificationKey := VerificationKey{
			PublicKey: keys.SigningKey.PublicKey,
			// After demoting the signing keyGenFunc, keep the token around for at least
			// the amount of time an ID Token is valid for. This ensures the
			// verification keyGenFunc won't expire until all ID Tokens it's signed
			// expired as well.
			Expiry: tNow.Add(k.strategy.idTokenValidFor),
		}
		keys.VerificationKeys = append(keys.VerificationKeys, verificationKey)
	}

	nextRotation = time.Now().Add(k.strategy.rotationFrequency)
	keys.SigningKey = key
	keys.NextRotation = nextRotation

	k.logger.Infof("keys rotated, next rotation: %s", nextRotation)

	return nil
}
