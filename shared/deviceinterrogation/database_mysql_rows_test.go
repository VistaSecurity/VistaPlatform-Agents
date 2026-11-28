package deviceinterrogation

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

type databaseScriptConnector struct{ script databaseScript }

func (c databaseScriptConnector) Connect(context.Context) (driver.Conn, error) {
	return &databaseScriptConn{script: c.script}, nil
}
func (c databaseScriptConnector) Driver() driver.Driver { return databaseScriptDriver{} }

type databaseScriptDriver struct{}

func (databaseScriptDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type databaseScript struct {
	session       [][]driver.Value
	sessionErrAt  int
	settings      [][]driver.Value
	settingsErrAt int
}
type databaseScriptConn struct{ script databaseScript }

func (*databaseScriptConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*databaseScriptConn) Close() error                        { return nil }
func (*databaseScriptConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (*databaseScriptConn) Ping(context.Context) error          { return nil }
func (c *databaseScriptConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case query == "SELECT VERSION()":
		return &databaseScriptRows{columns: []string{"version"}, data: [][]driver.Value{{"8.4.3"}}, errAt: -1}, nil
	case strings.HasPrefix(query, "SHOW SESSION STATUS"):
		return &databaseScriptRows{columns: []string{"name", "value"}, data: c.script.session, errAt: c.script.sessionErrAt}, nil
	case query == mysqlSettingsQuery && strings.Contains(query, "'require_secure_transport'"):
		return &databaseScriptRows{columns: []string{"name", "value"}, data: c.script.settings, errAt: c.script.settingsErrAt}, nil
	default:
		return nil, errors.New("unexpected query")
	}
}

type databaseScriptRows struct {
	columns []string
	data    [][]driver.Value
	errAt   int
	index   int
}

func (r *databaseScriptRows) Columns() []string { return r.columns }
func (*databaseScriptRows) Close() error        { return nil }
func (r *databaseScriptRows) Next(dest []driver.Value) error {
	if r.errAt >= 0 && r.index == r.errAt {
		r.index++
		return errors.New("scripted rowset failure")
	}
	if r.index >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.index])
	r.index++
	return nil
}

func TestMySQLSessionEvidenceRequiresCompleteExplicitRows(t *testing.T) {
	tests := []struct {
		name         string
		script       databaseScript
		wantState    DatabaseMeasurementState
		wantValue    *bool
		wantEnforced DatabaseMeasurementState
	}{
		{name: "missing cipher", script: databaseScript{session: [][]driver.Value{{"Ssl_version", "TLSv1.3"}}, sessionErrAt: -1, settings: [][]driver.Value{{"require_secure_transport", "ON"}}, settingsErrAt: -1}, wantState: DatabaseUnknown, wantEnforced: DatabaseMeasured},
		{name: "malformed scan", script: databaseScript{session: [][]driver.Value{{nil, "TLSv1.3"}}, sessionErrAt: -1, settings: [][]driver.Value{{"require_secure_transport", "ON"}}, settingsErrAt: -1}, wantState: DatabaseQueryError, wantEnforced: DatabaseMeasured},
		{name: "mid rowset error", script: databaseScript{session: [][]driver.Value{{"Ssl_cipher", "TLS_AES_256_GCM_SHA384"}}, sessionErrAt: 1, settings: [][]driver.Value{{"require_secure_transport", "ON"}}, settingsErrAt: -1}, wantState: DatabaseQueryError, wantEnforced: DatabaseMeasured},
		{name: "unrecognized enforcement", script: databaseScript{session: [][]driver.Value{{"Ssl_cipher", ""}}, sessionErrAt: -1, settings: [][]driver.Value{{"require_secure_transport", "sometimes"}}, settingsErrAt: -1}, wantState: DatabaseMeasured, wantValue: boolPointer(false), wantEnforced: DatabaseUnknown},
		{name: "explicit empty cipher", script: databaseScript{session: [][]driver.Value{{"Ssl_cipher", ""}, {"Ssl_version", ""}}, sessionErrAt: -1, settings: [][]driver.Value{{"require_secure_transport", "OFF"}}, settingsErrAt: -1}, wantState: DatabaseMeasured, wantValue: boolPointer(false), wantEnforced: DatabaseMeasured},
		{name: "settings rowset error", script: databaseScript{session: [][]driver.Value{{"Ssl_cipher", "TLS_AES_256_GCM_SHA384"}}, sessionErrAt: -1, settings: [][]driver.Value{{"require_secure_transport", "ON"}}, settingsErrAt: 1}, wantState: DatabaseMeasured, wantValue: boolPointer(true), wantEnforced: DatabaseQueryError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := dbOpenMySQL
			t.Cleanup(func() { dbOpenMySQL = original })
			dbOpenMySQL = func(*mysql.Config) (*sql.DB, error) {
				return sql.OpenDB(databaseScriptConnector{script: tc.script}), nil
			}
			o, err := dbInterrogateMySQL(context.Background(), "u:p@tcp(127.0.0.1:3306)/")
			if err != nil {
				t.Fatalf("interrogate: %v", err)
			}
			if o.SessionTLSInUse.State != tc.wantState {
				t.Fatalf("session state = %s, want %s", o.SessionTLSInUse.State, tc.wantState)
			}
			if tc.wantValue != nil && (o.SessionTLSInUse.Value == nil || *o.SessionTLSInUse.Value != *tc.wantValue) {
				t.Fatalf("session value = %v, want %v", o.SessionTLSInUse.Value, *tc.wantValue)
			}
			if o.TLSEnforced.State != tc.wantEnforced {
				t.Fatalf("enforcement state = %s, want %s", o.TLSEnforced.State, tc.wantEnforced)
			}
		})
	}
}

func boolPointer(v bool) *bool { return &v }
