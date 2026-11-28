package deviceinterrogation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation/internal/dialguard"
	"github.com/vistasecurity/vistaplatform-agents/shared/redact"
)

// DatabaseInterrogator collects facts about the SQL session and selected
// server settings. Policy judgment belongs to Vista Platform.
type DatabaseInterrogator struct{}

func (*DatabaseInterrogator) SupportedDeviceTypes() []string { return []string{"postgresql", "mysql"} }

// DatabaseMeasurementState distinguishes an observed false or empty value from
// evidence the collector could not obtain.
type DatabaseMeasurementState string

const (
	DatabaseMeasured    DatabaseMeasurementState = "measured"
	DatabaseUnknown     DatabaseMeasurementState = "unknown"
	DatabaseQueryError  DatabaseMeasurementState = "query_error"
	DatabaseUnsupported DatabaseMeasurementState = "unsupported"
)

type DatabaseBoolObservation struct {
	State DatabaseMeasurementState `json:"state"`
	Value *bool                    `json:"value,omitempty"`
}

type DatabaseStringObservation struct {
	State DatabaseMeasurementState `json:"state"`
	Value *string                  `json:"value,omitempty"`
}

// DatabaseObservation is the typed managed result. Engine and port are target
// assertions only; the platform binds them to the authenticated job.
type DatabaseObservation struct {
	Engine       string `json:"engine"`
	Port         int    `json:"port"`
	Hostname     string `json:"hostname,omitempty"`
	InstanceName string `json:"instance_name,omitempty"`

	ServerVersion             DatabaseStringObservation `json:"server_version"`
	SessionTLSInUse           DatabaseBoolObservation   `json:"session_tls_in_use"`
	SessionTLSVersion         DatabaseStringObservation `json:"session_tls_version"`
	SessionTLSCipher          DatabaseStringObservation `json:"session_tls_cipher"`
	TLSEnforced               DatabaseBoolObservation   `json:"tls_enforced"`
	EncryptionAtRestEnabled   DatabaseBoolObservation   `json:"encryption_at_rest_enabled"`
	EncryptionMethod          DatabaseStringObservation `json:"encryption_method"`
	EncryptionAlgorithm       DatabaseStringObservation `json:"encryption_algorithm"`
	PasswordEncryptionDefault DatabaseStringObservation `json:"password_encryption_default"`
	RawConfig                 map[string]interface{}    `json:"raw_config,omitempty"`

	Warnings []CollectionWarning `json:"-"`
}

func boolMeasured(v bool) DatabaseBoolObservation {
	return DatabaseBoolObservation{State: DatabaseMeasured, Value: &v}
}
func stringMeasured(v string) DatabaseStringObservation {
	return DatabaseStringObservation{State: DatabaseMeasured, Value: &v}
}
func boolState(s DatabaseMeasurementState) DatabaseBoolObservation {
	return DatabaseBoolObservation{State: s}
}
func stringState(s DatabaseMeasurementState) DatabaseStringObservation {
	return DatabaseStringObservation{State: s}
}

var (
	dbInterrogatePostgres = dbInterrogatePostgreSQL
	dbInterrogateMy       = dbInterrogateMySQL
	dbOpenMySQL           = func(cfg *mysql.Config) (*sql.DB, error) {
		connector, err := mysql.NewConnector(cfg)
		if err != nil {
			return nil, err
		}
		return sql.OpenDB(connector), nil
	}
)

func InterrogateDatabase(ctx context.Context, device DeviceInfo, creds Credentials) (*DatabaseObservation, error) {
	connStr, port, err := dbBuildConnStr(device, creds)
	if err != nil {
		return nil, fmt.Errorf("failed to build connection string: %w", err)
	}
	var observation *DatabaseObservation
	switch device.DeviceType {
	case "postgresql":
		observation, err = dbInterrogatePostgres(ctx, connStr)
	case "mysql":
		observation, err = dbInterrogateMy(ctx, connStr)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", device.DeviceType)
	}
	if err != nil {
		return nil, fmt.Errorf("database interrogation failed: %w", err)
	}
	observation.Hostname, _ = deviceHost(device)
	observation.Port = port
	observation.RawConfig = redact.Map(observation.RawConfig)
	if err := ValidateDatabaseObservation(*observation); err != nil {
		return nil, fmt.Errorf("invalid database observation: %w", err)
	}
	return observation, nil
}

var databaseRawKeys = map[string]map[string]bool{
	"postgresql": {
		"version": true, "session_tls_in_use": true, "session_tls_version": true,
		"session_tls_cipher": true, "ssl": true, "ssl_min_protocol_version": true,
		"ssl_max_protocol_version": true, "ssl_ciphers": true,
		"ssl_prefer_server_ciphers": true, "password_encryption": true,
	},
	"mysql": {
		"version": true, "session_tls_in_use": true, "session_tls_version": true,
		"session_tls_cipher": true, "have_ssl": true, "have_openssl": true,
		"tls_version": true, "tls_ciphersuites": true, "require_secure_transport": true,
		"default_table_encryption": true, "innodb_encrypt_tables": true,
		"binlog_encryption": true, "table_encryption_privilege_check": true,
	},
}

// ValidateDatabaseObservation enforces the same bounded fact contract as the
// managed JSON schema. It is exported for the paired Platform ingest boundary.
func ValidateDatabaseObservation(o DatabaseObservation) error {
	allowed, ok := databaseRawKeys[o.Engine]
	if !ok {
		return fmt.Errorf("unsupported engine")
	}
	if o.Port < 1 || o.Port > 65535 {
		return fmt.Errorf("invalid port")
	}
	if len(o.Hostname) > 255 || len(o.InstanceName) > 255 {
		return fmt.Errorf("database identity exceeds bound")
	}
	stringsToCheck := []struct {
		v   DatabaseStringObservation
		max int
	}{
		{o.ServerVersion, 512}, {o.SessionTLSVersion, 64}, {o.SessionTLSCipher, 255},
		{o.EncryptionMethod, 255}, {o.EncryptionAlgorithm, 255}, {o.PasswordEncryptionDefault, 100},
	}
	for _, item := range stringsToCheck {
		if err := validateStringObservation(item.v, item.max); err != nil {
			return err
		}
	}
	for _, value := range []DatabaseBoolObservation{o.SessionTLSInUse, o.TLSEnforced, o.EncryptionAtRestEnabled} {
		if err := validateBoolObservation(value); err != nil {
			return err
		}
	}
	for key, value := range o.RawConfig {
		if !allowed[key] {
			return fmt.Errorf("raw setting is not allowlisted")
		}
		switch v := value.(type) {
		case string:
			if len(v) > 2048 {
				return fmt.Errorf("raw setting exceeds bound")
			}
		case bool, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		default:
			return fmt.Errorf("raw setting has unsupported type")
		}
	}
	encoded, err := json.Marshal(o.RawConfig)
	if err != nil || len(encoded) > 16*1024 {
		return fmt.Errorf("raw settings exceed bound")
	}
	return nil
}

func validateBoolObservation(value DatabaseBoolObservation) error {
	switch value.State {
	case DatabaseMeasured:
		if value.Value == nil {
			return fmt.Errorf("measured boolean lacks value")
		}
	case DatabaseUnknown, DatabaseQueryError, DatabaseUnsupported:
		if value.Value != nil {
			return fmt.Errorf("non-measured boolean carries value")
		}
	default:
		return fmt.Errorf("invalid measurement state")
	}
	return nil
}

func validateStringObservation(value DatabaseStringObservation, max int) error {
	switch value.State {
	case DatabaseMeasured:
		if value.Value == nil || *value.Value == "" {
			return fmt.Errorf("measured string lacks value")
		}
		if len(*value.Value) > max {
			return fmt.Errorf("measured string exceeds bound")
		}
	case DatabaseUnknown, DatabaseQueryError, DatabaseUnsupported:
		if value.Value != nil {
			return fmt.Errorf("non-measured string carries value")
		}
	default:
		return fmt.Errorf("invalid measurement state")
	}
	return nil
}

func (*DatabaseInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	observation, err := InterrogateDatabase(ctx, device, creds)
	if err != nil {
		return nil, err
	}
	var assets []CryptoAsset
	if observation.SessionTLSInUse.State == DatabaseMeasured && observation.SessionTLSInUse.Value != nil && *observation.SessionTLSInUse.Value {
		asset := CryptoAsset{
			Hostname: observation.Hostname, IPAddress: device.IPAddress, Port: observation.Port,
			Protocol: "TLS", AssetType: "database",
			Metadata: map[string]interface{}{
				"db_engine": observation.Engine, "db_version": observation.ServerVersion,
				"session_tls_in_use":          observation.SessionTLSInUse,
				"session_tls_cipher":          observation.SessionTLSCipher,
				"session_tls_version":         observation.SessionTLSVersion,
				"tls_enforced":                observation.TLSEnforced,
				"encryption_at_rest_enabled":  observation.EncryptionAtRestEnabled,
				"password_encryption_default": observation.PasswordEncryptionDefault,
				"raw_config":                  observation.RawConfig,
			},
		}
		if observation.SessionTLSVersion.State == DatabaseMeasured && observation.SessionTLSVersion.Value != nil {
			asset.ProtocolVersion = observation.SessionTLSVersion.Value
		}
		if observation.SessionTLSCipher.State == DatabaseMeasured && observation.SessionTLSCipher.Value != nil {
			asset.CipherSuite = observation.SessionTLSCipher.Value
		}
		assets = append(assets, asset)
	}
	return &InterrogateResult{
		Assets: assets,
		DeviceInfo: map[string]interface{}{
			"db_engine": observation.Engine, "db_version": observation.ServerVersion,
			"session_tls_in_use":          observation.SessionTLSInUse,
			"session_tls_cipher":          observation.SessionTLSCipher,
			"session_tls_version":         observation.SessionTLSVersion,
			"tls_enforced":                observation.TLSEnforced,
			"encryption_at_rest_enabled":  observation.EncryptionAtRestEnabled,
			"password_encryption_default": observation.PasswordEncryptionDefault,
			"raw_config":                  observation.RawConfig,
		},
		DatabaseObservations: []DatabaseObservation{*observation},
		Warnings:             observation.Warnings,
		collector:            databaseCollector,
	}, nil
}

func dbBuildConnStr(device DeviceInfo, creds Credentials) (string, int, error) {
	host, err := deviceHost(device)
	if err != nil {
		return "", 0, err
	}
	port := device.Port
	switch device.DeviceType {
	case "postgresql":
		if port == 0 {
			port = 5432
		}
		if port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid database port")
		}
		dsn := &url.URL{
			Scheme: "postgres",
			User:   url.UserPassword(creds.Username, creds.Password),
			Host:   net.JoinHostPort(host, strconv.Itoa(port)),
			Path:   "/postgres",
		}
		query := dsn.Query()
		query.Set("sslmode", "prefer")
		dsn.RawQuery = query.Encode()
		return dsn.String(), port, nil
	case "mysql":
		if port == 0 {
			port = 3306
		}
		if port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid database port")
		}
		cfg := mysql.NewConfig()
		cfg.User, cfg.Passwd, cfg.Net = creds.Username, creds.Password, "tcp"
		cfg.Addr, cfg.TLSConfig = net.JoinHostPort(host, strconv.Itoa(port)), "preferred"
		return cfg.FormatDSN(), port, nil
	default:
		return "", 0, fmt.Errorf("unsupported database type: %s", device.DeviceType)
	}
}

func newDatabaseObservation(engine string) *DatabaseObservation {
	return &DatabaseObservation{
		Engine: engine, RawConfig: make(map[string]interface{}),
		ServerVersion: stringState(DatabaseUnknown), SessionTLSInUse: boolState(DatabaseUnknown),
		SessionTLSVersion: stringState(DatabaseUnknown), SessionTLSCipher: stringState(DatabaseUnknown),
		TLSEnforced: boolState(DatabaseUnknown), EncryptionAtRestEnabled: boolState(DatabaseUnknown),
		EncryptionMethod: stringState(DatabaseUnknown), EncryptionAlgorithm: stringState(DatabaseUnknown),
		PasswordEncryptionDefault: stringState(DatabaseUnknown),
	}
}

func (o *DatabaseObservation) warning(endpoint string, err error, effect string) {
	o.Warnings = appendWarning(o.Warnings, sanitizeWarning(CollectionWarning{
		Collector: databaseCollector, Endpoint: endpoint, Reason: ClassifyWarningReason(err),
		Effect: effect, Detail: "database measurement failed",
	}))
}

func dbInterrogatePostgreSQL(ctx context.Context, connStr string) (*DatabaseObservation, error) {
	connector, err := pq.NewConnector(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	connector.Dialer(guardedPostgresDialer{})
	targetDB := sql.OpenDB(connector)
	defer func() { _ = targetDB.Close() }()
	targetDB.SetConnMaxLifetime(30 * time.Second)
	if err := targetDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	o := newDatabaseObservation("postgresql")
	var version string
	if err := targetDB.QueryRowContext(ctx, "SELECT version()").Scan(&version); err != nil {
		o.ServerVersion = stringState(DatabaseQueryError)
		o.warning("server-version", err, "server version not collected")
	} else {
		o.ServerVersion = stringMeasured(version)
		o.RawConfig["version"] = version
	}

	var tls bool
	var tlsVersion, cipher sql.NullString
	if err := targetDB.QueryRowContext(ctx, "SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&tls, &tlsVersion, &cipher); err != nil {
		o.SessionTLSInUse = boolState(DatabaseQueryError)
		o.SessionTLSVersion, o.SessionTLSCipher = stringState(DatabaseQueryError), stringState(DatabaseQueryError)
		o.warning("session-tls", err, "current SQL session TLS facts not collected")
	} else {
		o.SessionTLSInUse = boolMeasured(tls)
		o.RawConfig["session_tls_in_use"] = tls
		if tls && tlsVersion.Valid {
			o.SessionTLSVersion = stringMeasured(tlsVersion.String)
			o.RawConfig["session_tls_version"] = tlsVersion.String
		}
		if tls && cipher.Valid {
			o.SessionTLSCipher = stringMeasured(cipher.String)
			o.RawConfig["session_tls_cipher"] = cipher.String
		}
	}

	for _, setting := range []string{"ssl", "ssl_min_protocol_version", "ssl_max_protocol_version", "ssl_ciphers", "ssl_prefer_server_ciphers", "password_encryption"} {
		var name, value string
		err := targetDB.QueryRowContext(ctx, "SELECT name, setting FROM pg_settings WHERE name = $1", setting).Scan(&name, &value)
		if err != nil {
			if setting == "password_encryption" {
				o.PasswordEncryptionDefault = stringState(DatabaseQueryError)
			}
			o.warning("setting/"+setting, err, "database setting not collected")
			continue
		}
		o.RawConfig[name] = value
		if name == "password_encryption" {
			o.PasswordEncryptionDefault = stringMeasured(value)
		}
	}
	o.TLSEnforced = boolState(DatabaseUnsupported)
	o.EncryptionAtRestEnabled = boolState(DatabaseUnsupported)
	o.EncryptionMethod, o.EncryptionAlgorithm = stringState(DatabaseUnsupported), stringState(DatabaseUnsupported)
	return o, nil
}

var mysqlRetainedVariables = map[string]bool{
	"have_ssl": true, "have_openssl": true, "tls_version": true,
	"tls_ciphersuites": true, "require_secure_transport": true,
	"default_table_encryption": true, "innodb_encrypt_tables": true,
	"binlog_encryption": true, "table_encryption_privilege_check": true,
}

func mysqlConfig(connStr string) (*mysql.Config, error) {
	cfg, err := mysql.ParseDSN(connStr)
	if err != nil {
		return nil, err
	}
	cfg.Logger = &mysql.NopLogger{}
	cfg.DialFunc = dialguard.Dial(0)
	return cfg, nil
}

type guardedPostgresDialer struct{}

func (guardedPostgresDialer) Dial(network, address string) (net.Conn, error) {
	return dialguard.Dial(0)(context.Background(), network, address)
}
func (guardedPostgresDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return dialguard.Dial(timeout)(context.Background(), network, address)
}
func (guardedPostgresDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialguard.Dial(0)(ctx, network, address)
}

const mysqlSettingsQuery = "SHOW VARIABLES WHERE Variable_name IN ('have_ssl','have_openssl','tls_version','tls_ciphersuites','require_secure_transport','default_table_encryption','innodb_encrypt_tables','binlog_encryption','table_encryption_privilege_check')"

func dbInterrogateMySQL(ctx context.Context, connStr string) (*DatabaseObservation, error) {
	cfg, err := mysqlConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MySQL: %w", err)
	}
	targetDB, err := dbOpenMySQL(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MySQL: %w", err)
	}
	defer func() { _ = targetDB.Close() }()
	targetDB.SetConnMaxLifetime(30 * time.Second)
	if err := targetDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping MySQL: %w", err)
	}
	o := newDatabaseObservation("mysql")
	var version string
	if err := targetDB.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		o.ServerVersion = stringState(DatabaseQueryError)
		o.warning("server-version", err, "server version not collected")
	} else {
		o.ServerVersion = stringMeasured(version)
		o.RawConfig["version"] = version
	}

	rows, err := targetDB.QueryContext(ctx, "SHOW SESSION STATUS WHERE Variable_name IN ('Ssl_cipher','Ssl_version')")
	if err != nil {
		o.SessionTLSInUse = boolState(DatabaseQueryError)
		o.SessionTLSVersion, o.SessionTLSCipher = stringState(DatabaseQueryError), stringState(DatabaseQueryError)
		o.warning("session-tls", err, "current SQL session TLS facts not collected")
	} else {
		values, readErr := readMySQLRows(rows)
		_ = rows.Close()
		if readErr != nil {
			o.SessionTLSInUse = boolState(DatabaseQueryError)
			o.SessionTLSVersion, o.SessionTLSCipher = stringState(DatabaseQueryError), stringState(DatabaseQueryError)
			o.warning("session-tls", readErr, "current SQL session TLS facts not collected")
		} else if cipher, present := values["ssl_cipher"]; present {
			o.SessionTLSInUse = boolMeasured(cipher != "")
			o.RawConfig["session_tls_in_use"] = cipher != ""
			if cipher != "" {
				o.SessionTLSCipher = stringMeasured(cipher)
				o.RawConfig["session_tls_cipher"] = cipher
			}
			if tlsVersion, present := values["ssl_version"]; present && tlsVersion != "" {
				o.SessionTLSVersion = stringMeasured(tlsVersion)
				o.RawConfig["session_tls_version"] = tlsVersion
			}
		}
	}

	rows, err = targetDB.QueryContext(ctx, mysqlSettingsQuery)
	if err != nil {
		o.TLSEnforced = boolState(DatabaseQueryError)
		o.warning("server-settings", err, "database settings not collected")
	} else {
		values, readErr := readMySQLRows(rows)
		_ = rows.Close()
		if readErr != nil {
			o.TLSEnforced = boolState(DatabaseQueryError)
			o.warning("server-settings", readErr, "database settings not collected")
		} else {
			for name, value := range values {
				if mysqlRetainedVariables[name] {
					o.RawConfig[name] = value
				}
			}
			if value, present := values["require_secure_transport"]; present {
				switch strings.ToUpper(strings.TrimSpace(value)) {
				case "ON":
					o.TLSEnforced = boolMeasured(true)
				case "OFF":
					o.TLSEnforced = boolMeasured(false)
				default:
					o.TLSEnforced = boolState(DatabaseUnknown)
					o.warning("setting/require_secure_transport", fmt.Errorf("unrecognized boolean setting"), "TLS enforcement not determined")
				}
			}
		}
	}
	o.EncryptionAtRestEnabled = boolState(DatabaseUnknown)
	o.EncryptionMethod, o.EncryptionAlgorithm = stringState(DatabaseUnknown), stringState(DatabaseUnknown)
	o.PasswordEncryptionDefault = stringState(DatabaseUnsupported)
	return o, nil
}

type databaseRows interface {
	Next() bool
	Scan(...interface{}) error
	Err() error
}

func readMySQLRows(rows databaseRows) (map[string]string, error) {
	values := make(map[string]string)
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		values[strings.ToLower(name)] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func InterrogatePostgreSQLConn(ctx context.Context, connStr string) (*DatabaseObservation, error) {
	return redactedFinding(dbInterrogatePostgres(ctx, connStr))
}
func InterrogateMySQLConn(ctx context.Context, connStr string) (*DatabaseObservation, error) {
	return redactedFinding(dbInterrogateMy(ctx, connStr))
}
func redactedFinding(finding *DatabaseObservation, err error) (*DatabaseObservation, error) {
	if finding != nil {
		finding.RawConfig = redact.Map(finding.RawConfig)
	}
	return finding, err
}
