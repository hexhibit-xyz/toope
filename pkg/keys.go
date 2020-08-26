package pkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"io"
	"time"
)

// Keys hold encryption and signing keys.
type Keys struct {
	// Key for creating and verifying signatures. These may be nil.
	SigningKey    *jose.JSONWebKey
	SigningKeyPub *jose.JSONWebKey

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
	PublicKey *jose.JSONWebKey `json:"publicKey"`
	Expiry    time.Time        `json:"expiry"`
}

type keyRotater struct {
	keys     Keys
	strategy rotationStrategy
	logger   *logrus.Logger
	now      func() time.Time
}

// rotationStrategy describes a strategy for generating cryptographic keys, how
// often to rotate them, and how long they can validate signatures after rotation.
type rotationStrategy struct {
	// Time between rotations.
	rotationFrequency time.Duration

	// After being rotated how long should the keyGenFunc be kept around for validating
	// signatues?
	idTokenValidFor time.Duration

	algorithm  string
	keyGenFunc func() (interface{}, error)
}

type AsymmetricAlg interface {
	Public() AsymmetricAlg
}

func NewRotationStrategy(algorithm string, rotationFrequency, idTokenValidFor time.Duration) (rotationStrategy, error) {

	var keyGen func() (interface{}, error)

	keyGenRsa := func() (interface{}, error) {
		return rsa.GenerateKey(rand.Reader, 2048)
	}

	keyGenEcdsa := func() (interface{}, error) {
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	}

	switch algorithm {
	case "RS256":
		keyGen = keyGenRsa
	case "RS384":
		keyGen = keyGenRsa
	case "RS512":
		keyGen = keyGenRsa
	case "ES256":
		keyGen = keyGenEcdsa
	case "ES384":
		keyGen = keyGenEcdsa
	case "ES512":
		keyGen = keyGenEcdsa
	default:
		return rotationStrategy{}, fmt.Errorf("unsupported algorithm: '%s'", algorithm)
	}
	return rotationStrategy{
		rotationFrequency: rotationFrequency,
		idTokenValidFor:   idTokenValidFor,
		algorithm:         algorithm,
		keyGenFunc:        keyGen,
	}, nil
}

func NewRotater(strategy rotationStrategy) keyRotater {
	return keyRotater{
		keys:     Keys{},
		strategy: strategy,
		logger:   logrus.New(),
		now:      time.Now,
	}
}

func (k keyRotater) rotate() error {
	keys := k.keys
	k.logger.Infof("keys expired, rotating")

	// Generate the keyGenFunc outside of a storage transaction.
	key, err := k.strategy.keyGenFunc()
	if err != nil {
		return fmt.Errorf("generate keyGenFunc: %v", err)
	}
	b := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	keyID := hex.EncodeToString(b)
	priv := &jose.JSONWebKey{
		Key:       key,
		KeyID:     keyID,
		Algorithm: k.strategy.algorithm,
		Use:       "sig",
	}

	ecdsa, okE := key.(ecdsa.PrivateKey)
	rsa, okR := key.(rsa.PrivateKey)

	if !okE && !okR {
		return fmt.Errorf("key is not ECDSA nor RSA type")
	}

	var publicKey interface{}
	if okE {
		publicKey = ecdsa.Public()
	} else if okR {
		publicKey = rsa.Public()
	}

	pub := &jose.JSONWebKey{
		Key:       publicKey,
		KeyID:     keyID,
		Algorithm: k.strategy.algorithm,
		Use:       "sig",
	}

	var nextRotation time.Time
	tNow := k.now()

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

	if keys.SigningKeyPub != nil {
		// Move current signing keyGenFunc to a verification only keyGenFunc, throwing
		// away the private part.
		verificationKey := VerificationKey{
			PublicKey: keys.SigningKeyPub,
			// After demoting the signing keyGenFunc, keep the token around for at least
			// the amount of time an ID Token is valid for. This ensures the
			// verification keyGenFunc won't expire until all ID Tokens it's signed
			// expired as well.
			Expiry: tNow.Add(k.strategy.idTokenValidFor),
		}
		keys.VerificationKeys = append(keys.VerificationKeys, verificationKey)
	}

	nextRotation = k.now().Add(k.strategy.rotationFrequency)
	keys.SigningKey = priv
	keys.SigningKeyPub = pub
	keys.NextRotation = nextRotation

	k.keys = keys
	k.logger.Infof("keys rotated, next rotation: %s", nextRotation)

	return nil
}
