package des

import (
	"encoding/base64"
	"testing"
)

// go test -run TestTripleEcbDesEncrypt -v
func TestTripleEcbDesEncrypt(t *testing.T) {
	key := []byte("D7810B832347228614268233")
	plaintext := []byte("size=20&page=1&cityid=1")

	t.Logf("plaintext: %s, key: %s\n", string(plaintext), string(key))

	ciphertext, err := TripleEcbDesEncrypt(plaintext, key)
	if err != nil {
		t.Logf("TripleEcbDesEncrypt err: %s\n", err)
		return
	}

	base64Data := base64.StdEncoding.EncodeToString(ciphertext)
	t.Logf("base64 encode encrypt: %s", base64Data)
}

// go test -run TestTripleEcbDesDecrypt -v
func TestTripleEcbDesDecrypt(t *testing.T) {
	key := []byte("D7810B832347228614268233")
	base64Ciphertext := []byte("A7AoCHaBZDoQVRfZFXPzWek/CWuaiUZl")

	t.Logf("ciphertext: %s, key: %s\n", string(base64Ciphertext), string(key))

	// base64 decode
	ciphertext, err := base64.StdEncoding.DecodeString(string(base64Ciphertext))
	if err != nil {
		t.Logf("base64 decode ciphertext err: %s\n", err)
		return
	}

	plaintext, err := TripleEcbDesDecrypt(ciphertext, key)
	if err != nil {
		t.Logf("TripleEcbDesDecrypt err: %s", err)
		return
	}

	t.Logf("plaintext: %s\n", string(plaintext))
}
