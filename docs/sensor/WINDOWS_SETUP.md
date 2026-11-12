# Installing the sensor on Windows

`install-sensor.ps1` installs the Vista Platform sensor as a Windows service:
it starts at boot, the Service Control Manager restarts it after a failure, and
it registers itself with your Vista Platform on first start.

## What you need

- **Windows x64**: Windows 10 or 11, or Windows Server 2016 or later. The
  release also contains a Windows x86 (`windows_386`) sensor; it is
  compile-only (`runtime_qualified: false` in `agents-release.json`) and not
  supported.
- **An elevated (Administrator) PowerShell session.** Windows PowerShell 5.1,
  which ships with Windows, is enough.
- **Npcap**, which the sensor uses to capture packets. Download it from
  <https://npcap.com/#download>, run its installer as Administrator, and keep
  **"API-compatible Mode"** checked. Npcap is published under its own
  licence, whose free tier covers up to five systems; it is never bundled with
  the sensor. The installer checks for Npcap first and stops, changing nothing,
  if it is missing.
- **The commands from your console.** In your Vista Platform console, open
  Discovery → Sensors & Agents and choose **Register sensor or agent**. The
  dialog creates the registration key and prints the install commands for
  Windows, with your platform's URL and, where needed, its CA fingerprint (see
  below). You also need the address of this host that the key was created for
  (`-IP`).
- **The sensor for Windows** from the release page of the agents release your
  console names: the package `vista-sensor_<version>_windows_amd64.zip` (it
  holds `crypto-sensor.exe`, `install-sensor.ps1`, `LICENSE`, `NOTICE` and
  `THIRD_PARTY_LICENSES`), or the loose files
  `vista-sensor_<version>_windows_amd64.exe` and `install-sensor.ps1` in one
  directory. The installer takes the binary under either name; no rename is
  needed.

Verify what you downloaded before you run it: [verify-release.md](../verify-release.md).
The Windows binaries carry **no Authenticode signature**, so SmartScreen may
warn on first run; their Sigstore signature and `SHA256SUMS` are how to check
where they came from. Use the installer from the release, never a copy from this
repository's source tree.

## The platform URL and CA fingerprint

There is no hosted platform and no default URL: `-Url` is the address of your
own Vista Platform console, the URL the registration dialog was opened at. The
commands the dialog prints already carry it.

If your platform's certificate is signed by a private CA that this host does not
trust, the dialog shows a **Platform CA fingerprint** panel with a copy button,
and its commands carry `-CaFingerprint`. The value is the CA's SHA-256
fingerprint, 64 hexadecimal digits (colons and a `sha256:` prefix are accepted).
The sensor pins that CA on first start only if it has this fingerprint.

## Install

From an elevated PowerShell, in the directory holding the downloaded files:

```powershell
# The installer script is not signed, so Windows' default execution policy
# refuses to run it. This allows unsigned scripts for this PowerShell window
# only; it changes no machine or user setting.
Set-ExecutionPolicy -Scope Process Bypass
.\install-sensor.ps1 -CheckDependencies          # checks the binary runs here; installs nothing
.\install-sensor.ps1 -Url https://vista.example.com -IP 192.0.2.10 -KeyStdin
```

- `-KeyStdin` prompts for the registration key without echoing it, or reads the
  first line of standard input when it is redirected. `VISTA_REGISTRATION_KEY`
  in the environment also works; `-Key REG-...` is visible to other users while
  the installer runs. A registration key works once.
- `-Name NAME`: the sensor's name (default: the host name and the date).
- `-Interfaces LIST`: the adapters to capture on, comma-separated, each named as
  Windows shows it (`Ethernet 2`, `Wi-Fi`), by its description, or by its Npcap
  device name (`\Device\NPF_{GUID}`). Without it the sensor captures on every
  adapter that is up and has an address.
- `-CaFingerprint SHA256`: pin a private platform CA (see above).
- `-InstallDir DIRECTORY`: default `%ProgramFiles%\VistaSensor`.

`-Profile` is accepted and not applied yet: the sensor registers with the
`datacenter_host` profile.

## What it does

1. Checks that Npcap is installed, before it changes anything.
2. Creates `%ProgramFiles%\VistaSensor` and restricts it to **Administrators
   and SYSTEM**: the configuration holds the registration key until the sensor
   redeems it, and `data\certs` holds the sensor's private key.
3. Copies the binary there as `crypto-sensor.exe` and writes
   `sensor-config.yaml` with the platform URL, the key, the interfaces and the
   data path (`data\` inside the install directory).
4. Installs the service **`VistaSensor`** (display name "Vista Platform Crypto
   Sensor"), which runs `crypto-sensor.exe --verbose -config <sensor-config.yaml>`.
   It starts on boot, and the Service Control Manager restarts it 10 seconds
   after a failure.
5. Starts it and waits for the sensor to **register itself**. The installer
   never registers on the sensor's behalf: the sensor generates its key pair on
   the host, sends a certificate request with the key, and writes the UUID it
   was given back into `sensor-config.yaml`.

If the platform rejects the key (invalid, expired or already used), the
installer stops and disables the service and asks for a new key. If the sensor
has not registered in time for any other reason, the service keeps running and
retrying, and the installer says where to look.

## Running it

| | |
|---|---|
| Status | `Get-Service VistaSensor` |
| Log | `Get-Content -Tail 50 -Wait "$env:ProgramFiles\VistaSensor\data\logs\sensor.log"` (rotates at 10 MB to `sensor.log.1`) |
| Service events | `Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='VistaSensor'} -MaxEvents 20` |
| Stop | `Stop-Service VistaSensor` |
| Restart | `Restart-Service VistaSensor` |

The sensor makes **outbound connections only** to your platform; it opens no
inbound port. If outbound traffic is filtered, allow HTTPS from
`crypto-sensor.exe` to the platform's address.

## Upgrade

Download and verify the new release, then run its installer again from the
directory holding the new files, with **no key**:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-sensor.ps1
```

It keeps the sensor's identity, configuration and certificate and replaces only
the binary.

A registration key cannot be used twice. Running the installer with a **new**
key registers this host as a **second, new sensor**: the old certificate is
removed and the old sensor stays in the console until you remove it there. Do
that only to replace the sensor's identity on purpose.

## Uninstall

From an elevated PowerShell, in the directory holding the installer:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-sensor.ps1 -Uninstall
```

It stops and removes the `VistaSensor` service and the installation. The sensor
stays listed in the console until you remove it there. Npcap stays installed;
remove it from Settings → Apps if nothing else uses it.

## Troubleshooting

| What you see | What to do |
|---|---|
| `install-sensor.ps1 cannot be loaded because running scripts is disabled` | Run `Set-ExecutionPolicy -Scope Process Bypass` in the same window first. |
| The installer says Npcap is not installed | Install Npcap from <https://npcap.com/#download> with "API-compatible Mode" checked, then run the installer again. |
| `couldn't load wpcap.dll` in the log | Npcap is missing or was removed: reinstall it as above and restart the service. |
| No adapter to capture on, or an `-Interfaces` name not found | Run the installer again with `-Interfaces` naming the adapter as `Get-NetAdapter` shows it. The sensor checks that capture can start before it registers, so a failed check does not use the key. |
| The key was rejected | Create a new key in the console and run the installer again with it. |
| Antivirus blocks capture | Add `%ProgramFiles%\VistaSensor\crypto-sensor.exe` to its exclusions. |

More: [WINDOWS_USAGE.md](WINDOWS_USAGE.md) (running the sensor by hand, file
locations), [CERTIFICATE_MANAGEMENT.md](CERTIFICATE_MANAGEMENT.md).
