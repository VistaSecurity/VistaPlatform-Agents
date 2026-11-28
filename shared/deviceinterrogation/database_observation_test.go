package deviceinterrogation

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validDatabaseObservation() DatabaseObservation {
	return DatabaseObservation{
		Engine: "postgresql", Port: 5432,
		ServerVersion:             stringMeasured("PostgreSQL 17"),
		SessionTLSInUse:           boolMeasured(false),
		SessionTLSVersion:         stringState(DatabaseUnknown),
		SessionTLSCipher:          stringState(DatabaseUnknown),
		TLSEnforced:               boolState(DatabaseUnsupported),
		EncryptionAtRestEnabled:   boolState(DatabaseUnsupported),
		EncryptionMethod:          stringState(DatabaseUnsupported),
		EncryptionAlgorithm:       stringState(DatabaseUnsupported),
		PasswordEncryptionDefault: stringMeasured("scram-sha-256"),
		RawConfig:                 map[string]interface{}{"session_tls_in_use": false, "password_encryption": "scram-sha-256"},
	}
}

func TestDatabaseWarningDoesNotExposeDriverError(t *testing.T) {
	o := validDatabaseObservation()
	o.warning("settings", errors.New("open /var/lib/mysql/private.pem with password hunter2"), "settings not collected")
	encoded, err := json.Marshal(o.Warnings)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, secret := range []string{"/var/lib/mysql/private.pem", "hunter2"} {
		if strings.Contains(text, secret) {
			t.Fatalf("driver error detail escaped in warning: %s", text)
		}
	}
	if len(o.Warnings) != 1 || o.Warnings[0].Detail != "database measurement failed" {
		t.Fatalf("warning = %+v", o.Warnings)
	}
}

func TestDatabaseObservationMeasuredFalseAndNoVerdict(t *testing.T) {
	o := validDatabaseObservation()
	if err := ValidateDatabaseObservation(o); err != nil {
		t.Fatalf("valid observation: %v", err)
	}
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, `"session_tls_in_use":{"state":"measured","value":false}`) {
		t.Fatalf("measured false did not survive JSON: %s", text)
	}
	for _, retired := range []string{"risk_score", "weak", "compliant", "noncompliant"} {
		if strings.Contains(text, retired) {
			t.Fatalf("retired judgment %q present: %s", retired, text)
		}
	}
}

func TestDatabaseObservationRejectsInvalidStateAndRawSettings(t *testing.T) {
	falseValue := false
	tests := map[string]func(*DatabaseObservation){
		"unknown with value": func(o *DatabaseObservation) {
			o.SessionTLSInUse = DatabaseBoolObservation{State: DatabaseUnknown, Value: &falseValue}
		},
		"measured without value": func(o *DatabaseObservation) { o.SessionTLSInUse = DatabaseBoolObservation{State: DatabaseMeasured} },
		"unallowlisted raw":      func(o *DatabaseObservation) { o.RawConfig["ssl_key_file"] = "/secret/key.pem" },
		"oversize raw":           func(o *DatabaseObservation) { o.RawConfig["ssl_ciphers"] = strings.Repeat("x", 2049) },
		"invalid port":           func(o *DatabaseObservation) { o.Port = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			o := validDatabaseObservation()
			mutate(&o)
			if err := ValidateDatabaseObservation(o); err == nil {
				t.Fatal("invalid observation accepted")
			}
		})
	}
}
