package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocolschema"
	di "github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation"
)

func TestDatabaseObservationManagedSchema(t *testing.T) {
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	falseValue := false
	text := func(v string) *string { return &v }
	result := JobResult{JobID: uuid.New(), Success: true, CompletedAt: time.Now(), DatabaseObservations: []di.DatabaseObservation{{
		Engine: "postgresql", Port: 5432,
		ServerVersion:             di.DatabaseStringObservation{State: di.DatabaseMeasured, Value: text("PostgreSQL 17")},
		SessionTLSInUse:           di.DatabaseBoolObservation{State: di.DatabaseMeasured, Value: &falseValue},
		SessionTLSVersion:         di.DatabaseStringObservation{State: di.DatabaseUnknown},
		SessionTLSCipher:          di.DatabaseStringObservation{State: di.DatabaseUnknown},
		TLSEnforced:               di.DatabaseBoolObservation{State: di.DatabaseUnsupported},
		EncryptionAtRestEnabled:   di.DatabaseBoolObservation{State: di.DatabaseUnsupported},
		EncryptionMethod:          di.DatabaseStringObservation{State: di.DatabaseUnsupported},
		EncryptionAlgorithm:       di.DatabaseStringObservation{State: di.DatabaseUnsupported},
		PasswordEncryptionDefault: di.DatabaseStringObservation{State: di.DatabaseMeasured, Value: text("scram-sha-256")},
		RawConfig:                 map[string]interface{}{"session_tls_in_use": false},
	}}}
	if err := set.Validate("job-result.device-agent", result); err != nil {
		t.Fatalf("valid managed result: %v", err)
	}

	result.DatabaseObservations[0].SessionTLSInUse = di.DatabaseBoolObservation{State: di.DatabaseUnknown, Value: &falseValue}
	if err := set.Validate("job-result.device-agent", result); err == nil {
		t.Fatal("schema accepted unknown state carrying a value")
	}
	result.DatabaseObservations[0].SessionTLSInUse = di.DatabaseBoolObservation{State: di.DatabaseMeasured, Value: &falseValue}
	result.DatabaseObservations = append(result.DatabaseObservations, result.DatabaseObservations[0])
	if err := set.Validate("job-result.device-agent", result); err == nil {
		t.Fatal("schema accepted more than one database observation")
	}
}
