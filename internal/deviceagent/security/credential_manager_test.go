package security

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestEncryptDecryptCredentials(t *testing.T) {
	original := map[string]interface{}{
		"username": "admin",
		"password": "super-secret-123",
		"api_key":  "ak-abc-def-ghi",
	}

	jobKey := "550e8400-e29b-41d4-a716-446655440000"
	regSecret := "registration-secret"

	// Encrypt
	envelope, err := EncryptCredentials(original, jobKey, regSecret)
	if err != nil {
		t.Fatalf("EncryptCredentials failed: %v", err)
	}

	// Verify envelope has encrypted_data field
	encData, ok := envelope["encrypted_data"].(string)
	if !ok || encData == "" {
		t.Fatal("encrypted envelope missing encrypted_data field")
	}

	// Verify encrypted data is not plaintext
	if encData == "admin" || encData == "super-secret-123" {
		t.Fatal("encrypted_data appears to contain plaintext")
	}

	// Decrypt
	decrypted, err := DecryptCredentials(envelope, jobKey, regSecret)
	if err != nil {
		t.Fatalf("DecryptCredentials failed: %v", err)
	}

	// Verify all fields match
	if decrypted["username"] != original["username"] {
		t.Errorf("username mismatch: got %v, want %v", decrypted["username"], original["username"])
	}
	if decrypted["password"] != original["password"] {
		t.Errorf("password mismatch: got %v, want %v", decrypted["password"], original["password"])
	}
	if decrypted["api_key"] != original["api_key"] {
		t.Errorf("api_key mismatch: got %v, want %v", decrypted["api_key"], original["api_key"])
	}
}

// Managed protocol 1 (D-P7): credentials travel sealed only. A plaintext map
// is refused — whatever secrets the agent holds — and never passed through.
func TestDecryptCredentials_UnsealedIsRefused(t *testing.T) {
	plaintext := map[string]interface{}{
		"username": "admin",
		"password": "secret",
	}
	for _, secrets := range [][]string{nil, {"agent-secret"}} {
		result, err := DecryptCredentials(plaintext, "any-key", secrets...)
		if !errors.Is(err, ErrUnsealedCredentials) || result != nil {
			t.Fatalf("DecryptCredentials(plaintext, %v) = %v, %v; want ErrUnsealedCredentials", secrets, result, err)
		}
	}
}

// No key is derived without an agent secret: neither the job-id-only key nor
// a registration key (the agent has none to pass).
func TestDecryptCredentials_NoAgentSecretOpensNothing(t *testing.T) {
	envelope, err := EncryptCredentials(map[string]interface{}{"password": "secret"}, "job-1", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, secrets := range [][]string{nil, {""}} {
		if got, err := DecryptCredentials(envelope, "job-1", secrets...); !errors.Is(err, ErrNoAgentSecret) || got != nil {
			t.Fatalf("DecryptCredentials(job-id-only envelope, %q) = %v, %v; want ErrNoAgentSecret", secrets, got, err)
		}
	}
}

// A job with no credentials at all has nothing to open.
func TestDecryptCredentials_NoCredentialsIsEmpty(t *testing.T) {
	for _, in := range []map[string]interface{}{nil, {}} {
		got, err := DecryptCredentials(in, "job-1")
		if err != nil || len(got) != 0 {
			t.Fatalf("DecryptCredentials(%v) = %v, %v; want an empty map", in, got, err)
		}
	}
}

func TestDecryptCredentials_WrongKey(t *testing.T) {
	original := map[string]interface{}{
		"username": "admin",
		"password": "secret",
	}

	// Encrypt with one key
	envelope, err := EncryptCredentials(original, "correct-key", "agent-secret")
	if err != nil {
		t.Fatalf("EncryptCredentials failed: %v", err)
	}

	// Decrypt with wrong key should fail
	_, err = DecryptCredentials(envelope, "wrong-key", "agent-secret")
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key, got nil")
	}
}

func TestDecryptCredentials_InvalidBase64(t *testing.T) {
	envelope := map[string]interface{}{
		"encrypted_data": "not-valid-base64!!!",
	}

	_, err := DecryptCredentials(envelope, "any-key", "agent-secret")
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestDecryptCredentials_TruncatedCiphertext(t *testing.T) {
	envelope := map[string]interface{}{
		"encrypted_data": "AAAA", // valid base64 but too short for GCM
	}

	_, err := DecryptCredentials(envelope, "any-key", "agent-secret")
	if err == nil {
		t.Fatal("expected error for truncated ciphertext, got nil")
	}
}

func TestEncryptCredentials_RoundTrip_ComplexPayload(t *testing.T) {
	original := map[string]interface{}{
		"username":    "admin@device.local",
		"password":    "p@$$w0rd!#%^&*()",
		"api_key":     "",
		"enable_pass": "enable-secret",
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	jobKey := "test-job-key-123"

	envelope, err := EncryptCredentials(original, jobKey, "secret")
	if err != nil {
		t.Fatalf("EncryptCredentials failed: %v", err)
	}

	decrypted, err := DecryptCredentials(envelope, jobKey, "secret")
	if err != nil {
		t.Fatalf("DecryptCredentials failed: %v", err)
	}

	// Compare JSON representations for deep equality
	origJSON, _ := json.Marshal(original)
	decJSON, _ := json.Marshal(decrypted)

	if string(origJSON) != string(decJSON) {
		t.Errorf("round-trip mismatch:\n  original:  %s\n  decrypted: %s", origJSON, decJSON)
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	key1 := DeriveKey("same-input", "")
	key2 := DeriveKey("same-input", "")

	if len(key1) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(key1))
	}

	for i := range key1 {
		if key1[i] != key2[i] {
			t.Fatal("DeriveKey is not deterministic")
		}
	}
}

func TestDeriveKey_DifferentInputs(t *testing.T) {
	key1 := DeriveKey("input-a", "")
	key2 := DeriveKey("input-b", "")

	same := true
	for i := range key1 {
		if key1[i] != key2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("DeriveKey produced same key for different inputs")
	}
}

func TestClearCredentials(t *testing.T) {
	creds := map[string]interface{}{
		"username": "admin",
		"password": "secret",
	}

	ClearCredentials(creds)

	if len(creds) != 0 {
		t.Errorf("expected empty map after ClearCredentials, got %d entries", len(creds))
	}
}

func TestEncryptDecrypt_Uniqueness(t *testing.T) {
	// Same plaintext encrypted twice should produce different ciphertexts (random nonce)
	original := map[string]interface{}{"password": "test"}
	jobKey := "key"

	env1, _ := EncryptCredentials(original, jobKey, "agent-secret")
	env2, _ := EncryptCredentials(original, jobKey, "agent-secret")

	if env1["encrypted_data"] == env2["encrypted_data"] {
		t.Fatal("two encryptions of same plaintext produced identical ciphertext (nonce reuse)")
	}

	// But both should decrypt to the same value
	dec1, _ := DecryptCredentials(env1, jobKey, "agent-secret")
	dec2, _ := DecryptCredentials(env2, jobKey, "agent-secret")

	if dec1["password"] != "test" || dec2["password"] != "test" {
		t.Fatal("different ciphertexts decrypted to different plaintexts")
	}
}
