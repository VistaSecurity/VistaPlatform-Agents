# The device agent on Windows

`install-device-agent.ps1` installs the device agent as a Windows service, the
counterpart of `install-device-agent.sh` on Linux: the same steps, and the same
re-run-to-upgrade behaviour.

## What you need

- Windows 10 or 11, or Windows Server 2016 or later, x86-64.
- An elevated (Administrator) PowerShell session. Windows PowerShell 5.1, which
  ships with Windows, is enough.
- A registration key for a device agent, from the console:
  Discovery → Sensors & Agents → Register → Device agent.
- The device agent for Windows from a release: the package
  `vista-device-agent_<version>_windows_amd64.zip` (it holds `device-agent.exe`
  and `install-device-agent.ps1`), or the loose files
  `vista-device-agent_<version>_windows_amd64.exe` and `install-device-agent.ps1`
  in one directory. The installer takes the binary under either name. Verify
  what you downloaded first ([verify-release.md](../verify-release.md)).

The Windows binary has no Authenticode signature. Its Sigstore signature and
`SHA256SUMS` are how to check it; SmartScreen may warn on first run.

## Install

From the directory holding the files:

```powershell
# The installer is not signed; allow it for this session only.
Set-ExecutionPolicy -Scope Process Bypass
.\install-device-agent.ps1 -Url https://vista.example.com -KeyStdin
```

`-KeyStdin` prompts for the key without echoing it, or reads the first line
of standard input when it is redirected, so the key never appears on a command
line or in the process list. The `VISTA_REGISTRATION_KEY` environment variable
also works, and so does `-Key REG-...` (visible to other users of the host
while the installer runs).

For a platform whose certificate is signed by a private CA this host does not
trust, add `-CaFingerprint <SHA-256 of the CA certificate>`: the agent pins the
platform's CA on first start only if it has that fingerprint.

To check the binary runs on this host without installing anything (no
Administrator rights or key needed):

```powershell
.\install-device-agent.ps1 -CheckDependencies
```

## What it does

1. Checks the binary runs on this host (`device-agent.exe -version`) before it
   changes anything.
2. Creates `%ProgramFiles%\VistaDeviceAgent` (`-InstallDir` to change it) and
   restricts it to **Administrators and SYSTEM**: the configuration holds the
   registration key until the agent redeems it, and `data\certs` holds the
   agent's private key.
3. Copies the binary there as `device-agent.exe` and writes
   `device-agent.yaml` with the platform URL, the key and the data path
   (`data\` inside the install directory).
4. Installs the service **`VistaDeviceAgent`** (Vista Platform Device Agent):
   it starts on boot, and the Service Control Manager restarts it 10 seconds
   after a failure.
5. Starts it and waits up to 90 seconds for the agent to **enroll itself**.
   The installer never registers on the agent's behalf: the agent generates
   its key pair on the host, sends a certificate request with the key, and
   writes the agent ID it was given back into `device-agent.yaml`. That ID is
   what the installer waits for.

If the platform rejects the key (invalid, expired or already used), the
installer prints the agent's own lines, stops and disables the service, and
asks for a new key. If the agent has not enrolled within 90 seconds for any
other reason, the service keeps running and retrying, and the installer says
where to look.

## Upgrade, re-run and a new key

Run the installer again with the **same key** to upgrade: it keeps the agent's
identity and configuration and replaces only the binary. With a **different
key** it starts a fresh enrollment: the previous certificate is removed and the
agent enrolls as a new agent.

## Running it

| | |
|---|---|
| Status | `Get-Service VistaDeviceAgent` |
| Log | `Get-Content -Tail 50 -Wait "$env:ProgramFiles\VistaDeviceAgent\data\logs\device-agent.log"` (rotates at 10 MB to `device-agent.log.1`) |
| Service events | `Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='VistaDeviceAgent'} -MaxEvents 20` |
| Restart | `Restart-Service VistaDeviceAgent` |
| Uninstall | `Stop-Service VistaDeviceAgent; sc.exe delete VistaDeviceAgent`, then delete the install directory |

A restart requested from the console stops the agent cleanly and the Service
Control Manager starts it again.
