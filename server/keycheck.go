package main

// The vault's key_check, made on the server by the admin so no device can pick
// the passphrase. Mirrors plugin/src/core/crypto.ts exactly:
//   master   = PBKDF2-SHA256(NFC(passphrase), salt, iters, 32 bytes)
//   enc      = HKDF-SHA256(master, salt 32 zero bytes, info "aizu-sync enc v1")
//   keycheck = base64(iv(12) || AES-256-GCM(enc, "aizu-sync key check v1", aad "keycheck"))
// The passphrase is used once in memory and never written anywhere.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const keyCheckText = "aizu-sync key check v1"

// ASCII only: Go's standard library has no NFC, and for ASCII NFC is the identity.
func checkPassphrase(p string) error {
	if len(p) < 12 {
		return errors.New("passphrase must be at least 12 characters")
	}
	for _, r := range p {
		if r < 0x20 || r > 0x7e {
			return errors.New("passphrase must be printable ASCII")
		}
	}
	return nil
}

func vaultCipher(passphrase, saltB64 string, iters int) (cipher.AEAD, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, err
	}
	master, err := pbkdf2.Key(sha256.New, passphrase, salt, iters, 32)
	if err != nil {
		return nil, err
	}
	enc, err := hkdf.Key(sha256.New, master, make([]byte, 32), "aizu-sync enc v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func makeKeyCheck(passphrase, saltB64 string, iters int) (string, error) {
	g, err := vaultCipher(passphrase, saltB64, iters)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 12)
	rand.Read(iv)
	return base64.StdEncoding.EncodeToString(g.Seal(iv, iv, []byte(keyCheckText), []byte("keycheck"))), nil
}

func verifyKeyCheck(passphrase, saltB64 string, iters int, kc string) bool {
	g, err := vaultCipher(passphrase, saltB64, iters)
	if err != nil {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(kc)
	if err != nil || len(b) < 12 {
		return false
	}
	pt, err := g.Open(nil, b[:12], b[12:], []byte("keycheck"))
	return err == nil && string(pt) == keyCheckText
}

// 25 characters from a 31-letter alphabet without look-alikes (~124 bits), in groups of 5.
func generatePassphrase() string {
	const abc = "abcdefghjkmnpqrstuvwxyz23456789"
	out := make([]byte, 0, 25)
	buf := make([]byte, 64)
	for len(out) < 25 {
		rand.Read(buf)
		for _, b := range buf {
			if b < 248 && len(out) < 25 { // 248 = 8*31: no modulo bias
				out = append(out, abc[int(b)%31])
			}
		}
	}
	var parts []string
	for i := 0; i < 25; i += 5 {
		parts = append(parts, string(out[i:i+5]))
	}
	return strings.Join(parts, "-")
}
