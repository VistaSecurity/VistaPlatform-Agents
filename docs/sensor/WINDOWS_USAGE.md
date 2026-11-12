# The sensor on Windows: operation and troubleshooting

## Setting it up

Set the sensor up with its installer, as [WINDOWS_SETUP.md](WINDOWS_SETUP.md)
describes: get the commands from your console (Discovery → Sensors & Agents →
**Register sensor or agent**), download and verify the release
([verify-release.md](../verify-release.md)), install Npcap, and run
`install-sensor.ps1` from an elevated PowerShell. It installs the `VistaSensor`
service, which starts at boot and registers itself with your platform.

## Files

Everything lives in the installation directory, `%ProgramFiles%\VistaSensor`,
which the installer restricts to Administrators and SYSTEM:

| Path | What it is |
|---|---|
| `crypto-sensor.exe` | the sensor |
| `sensor-config.yaml` | its configuration, which the service passes with `-config` |
| `data\certs\` | the sensor's certificate (`client.crt`), private key (`client.key`) and the platform CA (`ca.crt`), written after registration |
| `data\logs\sensor.log` | the sensor's log; moves to `sensor.log.1` at 10 MB |
| `data\platform-probe-consent.json` | the platform's probing settings as last delivered |

The service also writes start, stop and failure events to the Windows
Application log under the source `VistaSensor`:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='VistaSensor'} -MaxEvents 20
```

After registration the sensor loads its configuration and certificate from these
files on every start; it never needs the registration key again.

## Running the binary by hand (troubleshooting and evaluation)

Running `crypto-sensor.exe` in a console is for diagnosing a problem or for
trying the sensor without a platform; it is not how to set one up. Use an
elevated prompt (packet capture needs it), with Npcap installed.

Test mode captures and decodes traffic and writes what it found to
`<dataPath>\test-discoveries.log` instead of sending it to a platform; no key is
used. Give it a scratch configuration so it does not touch the installed sensor:

```powershell
New-Item -ItemType Directory -Force C:\SensorEval | Out-Null
@'
sensorId: 'sensor-eval'
controlPlaneUrl: 'https://vista.example.com'
capture:
  interfaces: []
storage:
  dataPath: 'C:\SensorEval\data'
'@ | Set-Content -Encoding ascii C:\SensorEval\sensor-config.yaml
.\crypto-sensor.exe -config C:\SensorEval\sensor-config.yaml -test -interactive=false
```

Single-quoted YAML values take backslashes literally, which is how the installer
writes Windows paths. Stop the sensor with Ctrl+C. The flags are listed in
[USAGE_GUIDE.md](USAGE_GUIDE.md).

To watch the installed sensor, read its log rather than starting a second copy:

```powershell
Get-Content -Tail 50 -Wait "$env:ProgramFiles\VistaSensor\data\logs\sensor.log"
```

It starts with `🚀 Starting Vista Platform Network Sensor v<version>`.

## Troubleshooting

1. **`couldn't load wpcap.dll`, or no interfaces available for capture.** Npcap
   is missing. Install it from <https://npcap.com/#download> with
   "API-compatible Mode" checked ([WINDOWS_SETUP.md](WINDOWS_SETUP.md)).
2. **Registration fails.** Check that this host reaches your platform's URL. A
   rejected key is invalid, expired or already used: create a new one in the
   console and run the installer again with it. A certificate error means this
   host does not trust the platform's certificate: use the CA fingerprint the
   console's registration dialog shows (`-CaFingerprint`).
3. **No traffic is reported.** Check the interfaces the log says the sensor
   captures on, and name the right adapter with `-Interfaces` (as `Get-NetAdapter`
   shows it) when you run the installer.

Certificates: [CERTIFICATE_MANAGEMENT.md](CERTIFICATE_MANAGEMENT.md).
