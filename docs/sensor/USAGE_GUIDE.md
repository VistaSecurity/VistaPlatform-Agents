# Running the Vista Platform sensor

## First-time setup

The supported way to set up a sensor is its installer, which installs it as a
service that starts at boot and registers itself with your platform:

1. In your Vista Platform console, open Discovery → Sensors & Agents and choose
   **Register sensor or agent**. The dialog creates a single-use registration
   key and prints the install commands for your system, with your platform's
   URL and, for a platform with a private CA, its CA fingerprint.
2. Download the sensor for your system from the release the console names.
3. Verify the download ([verify-release.md](../verify-release.md)).
4. Run the installer from the directory holding the downloaded files.

The guides for each system: [Linux](LINUX_SETUP.md), [macOS](MACOS_SETUP.md),
[Windows](WINDOWS_SETUP.md).

## The installed service

| | Linux | macOS | Windows |
|---|---|---|---|
| Service | `vista-sensor.service` | launchd job `io.vistasecurity.sensor` | service `VistaSensor` |
| Status | `systemctl status vista-sensor` | `sudo launchctl print system/io.vistasecurity.sensor` | `Get-Service VistaSensor` |
| Log | `journalctl -u vista-sensor -f` | `/Library/Logs/Vista/sensor/sensor.log` | `%ProgramFiles%\VistaSensor\data\logs\sensor.log` |
| Restart | `sudo systemctl restart vista-sensor` | `sudo launchctl kickstart -k system/io.vistasecurity.sensor` | `Restart-Service VistaSensor` |
| Configuration | `/opt/vista-sensor/sensor-config.yaml` | `/usr/local/vista-sensor/etc/sensor-config.yaml` | `%ProgramFiles%\VistaSensor\sensor-config.yaml` |
| Upgrade | run the new release's installer with no key | same | same |
| Uninstall | `sudo bash install-sensor.sh --uninstall` | `sudo bash install-sensor-macos.sh --uninstall` | `.\install-sensor.ps1 -Uninstall` (elevated) |

Every service manager restarts the sensor when it stops, except after exit
status 78: that means a person has to act (the registration key was rejected,
or the configuration cannot be used).

**Upgrading** keeps the sensor's identity: run the new release's installer with
no key. A registration key cannot be used twice, and a new key registers the
host as a second, new sensor.

Once registered, the sensor appears under Discovery → Sensors & Agents. It
loads its configuration and certificate from disk on every start, so it never
needs the registration key again.

## Running the binary by hand (troubleshooting and evaluation)

Running the sensor in the foreground is for diagnosing a problem or for trying
it without a platform. It is not how to set up a sensor: a sensor started by
hand is not a service, and does not survive a reboot or a logout.

### Flags

| Flag | Meaning |
|---|---|
| `-config FILE` | Configuration file to load (the installers pass theirs) |
| `-verbose` | Detailed logging; on by default, `-verbose=false` to quiet it |
| `-test` | Test mode: log discoveries and heartbeats to `<dataPath>/test-discoveries.log` instead of sending them to the platform |
| `-interactive` | Ask for the settings on the terminal and write a configuration file. It opens by itself when there is no configuration file and stdin is a terminal; `-interactive=false` skips it |
| `-ca-fingerprint SHA256` | Pin the platform's CA on first start, only if it has this SHA-256 fingerprint |
| `-register` | Register with the platform using the key in the configuration |
| `-version` | Print the version and exit |

There is no default platform URL to rely on: always give the sensor your own
platform's URL in `controlPlaneUrl`.

### Test mode, without a platform

Test mode captures and decodes traffic and writes what it found to a local file;
nothing is sent anywhere and no key is used. Give it a scratch configuration and
data directory so it does not touch an installed sensor:

```sh
mkdir -p /tmp/sensor-eval
cat > /tmp/sensor-eval/sensor-config.yaml <<'EOF'
sensorId: "sensor-eval"
controlPlaneUrl: "https://vista.example.com"
capture:
  interfaces: ["eth0"]
storage:
  dataPath: "/tmp/sensor-eval/data"
EOF
sudo ./crypto-sensor -config /tmp/sensor-eval/sensor-config.yaml -test -interactive=false
```

Packet capture needs root on Linux and macOS (or `CAP_NET_RAW` on Linux), and an
elevated prompt with Npcap installed on Windows. `test-discoveries.log` holds
one JSON object per line and moves to `test-discoveries.log.<unix time>` at
10 MB; the five most recent backups are kept. Stop the sensor with Ctrl+C.

### Watching an installed sensor

Read the service's own log first (table above): the installers run the sensor
with `--verbose`. It starts with a line like:

```text
🚀 Starting Vista Platform Network Sensor v<version>
```

followed by the configuration it loaded and, once it is up, whether it is
registered.

## Troubleshooting

| What you see | What to do |
|---|---|
| The installer says the registration key was rejected | The key is invalid, expired or already used. Create a new key in the console and run the installer again with it. |
| The sensor did not register within 90 seconds | It keeps retrying. Check that this host reaches your platform's URL, and read the service log. |
| A TLS or certificate error reaching the platform | The host does not trust the platform's certificate: re-run the install commands with the CA fingerprint the console's registration dialog shows (`--ca-fingerprint`, `-CaFingerprint`). |
| `Operation not permitted` or `permission denied` opening a capture | Run the installed service, which has the rights it needs; by hand, run as root or elevated. |
| No interfaces to capture on, or a named interface not found | Name the interfaces with `--interfaces` (Linux, macOS) or `-Interfaces` (Windows). The sensor checks that capture can start before it registers, so a failed check does not use the key. |
| Windows: `couldn't load wpcap.dll` | Install [Npcap](https://npcap.com/#download) with "API-compatible Mode" checked ([WINDOWS_SETUP.md](WINDOWS_SETUP.md)). |
| The sensor's certificate is lost or no longer accepted | See [CERTIFICATE_MANAGEMENT.md](CERTIFICATE_MANAGEMENT.md). |

## More

- Where the sensor keeps its files: [CONFIGURATION_AND_LOGS.md](CONFIGURATION_AND_LOGS.md)
- Every configuration key: [`examples/sensor/config.example.yaml`](../../examples/sensor/config.example.yaml)
- Windows specifics: [WINDOWS_USAGE.md](WINDOWS_USAGE.md)
