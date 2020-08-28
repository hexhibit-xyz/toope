package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	v1 "k8s.io/api/core/v1"
)

const BlockTypePrivate = "RSA PRIVATE KEY"
const BlockTypePublic = "RSA PUBLIC KEY"
const SecretKeyPrivateKey = "private_key"

func decodeRSA(key *rsa.PrivateKey) (private string, public string) {
	public = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  BlockTypePublic,
			Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
		},
	))

	private = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  BlockTypePrivate,
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	))

	return
}

func encodeRSA(private string) (*rsa.PrivateKey, error) {

	block, _ := pem.Decode([]byte(private))
	if block == nil || block.Type != BlockTypePrivate {
		return nil, fmt.Errorf("failed to decode PEM block containing private key, block type found '%s'", block.Type)
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func FromSecret(secret v1.Secret) (*rsa.PrivateKey, error) {
	privatePem := secret.StringData[SecretKeyPrivateKey]
	return encodeRSA(privatePem)
}

func ToSecret(key *rsa.PrivateKey) *v1.Secret {
	priv, _ := decodeRSA(key)
	return DecodedToSecret(priv)
}

func DecodedToSecret(private string) *v1.Secret {
	return &v1.Secret{
		StringData: map[string]string{SecretKeyPrivateKey: private},
	}
}

func CreateKeys() (private, public string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	private, public = decodeRSA(key)
	return
}
