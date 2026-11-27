package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
)

// The registration key is single use: the control plane spends it the moment
// it issues this sensor's certificate. A sensor that cannot keep that
// certificate has therefore lost its identity for good — after a restart it
// presents a spent key, is REJECTED, and the service manager loops. So the
// sensor proves it can store the result BEFORE anything is sent, and treats a
// failed save after registration as the fatal event it is.

// enrolledConfigFileName is the file a sensor configured by its environment
// alone (a container: no config file, DATA_PATH on a volume) records its
// enrollment in, under the data path. It is the first place
// findDefaultConfigFile looks, so the next start reads it and does not try the
// spent registration key again. The device agent's equivalent is
// agent-config.yaml.
const enrolledConfigFileName = "sensor-config.yaml"

// enrolledConfigPath is where an environment-configured sensor records its
// enrollment.
func enrolledConfigPath(dataPath string) string {
	return filepath.Join(dataPath, enrolledConfigFileName)
}

// checkEnrollmentWritable reports whether this process can write the
// certificate directory under dataPath and, when configPath is named, the
// existing config file there; with no config file, the data path itself, where
// the enrollment is then recorded (enrolledConfigPath). It creates what is
// missing (the same directories the save would create) and probes each with a
// file it removes again.
func checkEnrollmentWritable(dataPath, configPath string) error {
	certs := filepath.Join(dataPath, "certs")
	if err := os.MkdirAll(certs, 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %w", certs, err)
	}
	if err := probeWritable(certs); err != nil {
		return err
	}
	if configPath == "" {
		return probeWritable(dataPath)
	}
	// The config file is rewritten atomically (temp file + rename in its own
	// directory), so the directory must be writable, and the file must exist.
	if err := probeWritable(filepath.Dir(configPath)); err != nil {
		return err
	}
	f, err := os.OpenFile(configPath, os.O_WRONLY, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config file %s does not exist", configPath)
		}
		return fmt.Errorf("cannot write %s: %w", configPath, err)
	}
	return f.Close()
}

func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".write-check-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// enrollmentUnwritableMessage is what the operator is told when the preflight
// fails. Nothing has been sent, so the key is still good.
func enrollmentUnwritableMessage(err error, dataPath string) string {
	return fmt.Sprintf("this sensor cannot store its enrollment: %v\n"+
		"   Nothing was sent to the control plane — the registration key is still unused.\n"+
		"   Run the sensor as a user that can write %s and its config file,\n"+
		"   or set the data path in its config to a directory this user can write.", err, dataPath)
}

// enrollmentLostMessage is what the operator is told when the save fails AFTER
// registration. Unreachable once checkEnrollmentWritable has passed, barring a
// full disk or a race; honest if it happens anyway.
func enrollmentLostMessage(sensorID, path string, err error) string {
	return fmt.Sprintf("registered as sensor %s, but could not save %s: %v\n"+
		"   The registration key is now SPENT and this enrollment cannot be recovered.\n"+
		"   Delete the sensor in the console (Discovery → Sensors & Agents), generate a new key, and register again.",
		sensorID, path, err)
}

// persistEnrollment writes the certificates and then the sensor ID and
// certificate paths to the config file. A sensor configured by its environment
// alone has no config file, so one is created under the data path first
// (enrolledConfigPath) from the configuration it is running, and the sensor
// uses it from then on, as one an installer wrote. The returned error already
// names the path and says the key is spent.
func (s *Sensor) persistEnrollment() error {
	certsDir := filepath.Join(s.config.Storage.DataPath, "certs")
	if err := saveCertificates(s.config); err != nil {
		return errors.New(enrollmentLostMessage(s.config.SensorID, certsDir, err))
	}
	log.Printf("✅ Certificates saved to: %s", certsDir)

	if s.configPath == "" {
		path := enrolledConfigPath(s.config.Storage.DataPath)
		if err := writeEnrolledConfigFile(path, s.config); err != nil {
			return errors.New(enrollmentLostMessage(s.config.SensorID, path, err))
		}
		s.configPath = path
		log.Printf("📁 No config file was in use: the enrollment is recorded in %s, which the sensor reads on its next start", path)
	}
	if err := s.saveConfigFile(); err != nil {
		return errors.New(enrollmentLostMessage(s.config.SensorID, s.configPath, err))
	}
	log.Printf("💾 Configuration saved to file with sensor ID")
	return nil
}

// writeEnrolledConfigFile creates the config file of a sensor that was
// configured by its environment alone, holding the settings it is running with
// (so the next start, which reads this file, runs the same way). The identity
// is added by saveConfigFile, exactly as for an installer's file: the sensor
// ID, the certificate paths and, once the agent secret is on disk, the
// registration key's fingerprint instead of the key. No certificate or key is
// written here; they are files of their own under certs/. Owner-only (0600),
// like every config file the sensor writes.
func writeEnrolledConfigFile(path string, cfg *config.Config) error {
	var f config.ConfigFile
	f.ControlPlaneURL = cfg.ControlPlaneURL
	f.RegistrationKey = cfg.RegistrationKey
	f.ReportingIntervalSecs = int(cfg.ReportingInterval / time.Second)
	f.HeartbeatIntervalSecs = int(cfg.HeartbeatInterval / time.Second)
	f.Storage.DataPath = cfg.Storage.DataPath
	c := &cfg.Capture
	fc := &f.Capture
	fc.Disabled = c.Disabled
	fc.Interfaces = c.Interfaces
	fc.ActiveProbing = c.ActiveProbing
	fc.ThirdPartyTLSEnrichment = c.ThirdPartyTLSEnrichment
	fc.OwnedNetworks = c.OwnedNetworks
	fc.NetworkDiscovery = c.NetworkDiscovery
	fc.MaxConnections = c.MaxConnections
	fc.TimeoutSeconds = c.TimeoutSeconds
	fc.BufferSize = c.BufferSize
	fc.ExtraPortsToMonitor = c.ExtraPortsToMonitor
	fc.DeepScan = c.DeepScan
	fc.DedupTTLMinutes = c.DedupTTLMinutes
	fc.STARTTLSPorts = c.STARTTLSPorts
	fc.EnableJA3 = boolPtr(c.EnableJA3)
	fc.EnableSTARTTLS = boolPtr(c.EnableSTARTTLS)
	fc.EnableQUICDecrypt = boolPtr(c.EnableQUICDecrypt)
	fc.EnableWireGuard = boolPtr(c.EnableWireGuard)
	fc.EnableSMB = boolPtr(c.EnableSMB)
	fc.EnableOpenVPN = boolPtr(c.EnableOpenVPN)
	fc.EnableKerberos = boolPtr(c.EnableKerberos)
	fc.EnableModbus = boolPtr(c.EnableModbus)
	fc.EnableMMS = boolPtr(c.EnableMMS)
	fc.EnableDNP3 = boolPtr(c.EnableDNP3)
	fc.EnableOPCUA = boolPtr(c.EnableOPCUA)
	fc.EnableENIP = boolPtr(c.EnableENIP)
	fc.EnableHARTIP = boolPtr(c.EnableHARTIP)
	fc.HostObservation = boolPtr(c.HostObservation)
	fc.HostObservationWindowSeconds = c.HostObservationWindowSeconds
	fc.HostObservationDNS = boolPtr(c.HostObservationDNS)
	f.TestMode = cfg.TestMode
	f.Verbose = cfg.Verbose

	var root yaml.Node
	if err := root.Encode(&f); err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	// saveConfigFile writes these, and a key written twice would make the file
	// unreadable; an unset verbose stays unset rather than null.
	for _, key := range []string{"sensorId", "registrationKeySha256", "security"} {
		removeMappingKey(&root, key)
	}
	if cfg.Verbose == nil {
		removeMappingKey(&root, "verbose")
	}
	if cfg.RegistrationKey == "" {
		removeMappingKey(&root, "registrationKey")
	}
	doc := &yaml.Node{
		Kind:        yaml.DocumentNode,
		Content:     []*yaml.Node{&root},
		HeadComment: "Vista Platform Network Sensor Configuration\nWritten at enrollment from the environment configuration; the sensor reads it on every start",
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	// Two-space lists, as the installer writes them: the interface update edits them.
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	return writeSecretConfigFile(path, out.Bytes())
}

func boolPtr(v bool) *bool { return &v }

// removeMappingKey drops key and its value from a YAML mapping node.
func removeMappingKey(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}
