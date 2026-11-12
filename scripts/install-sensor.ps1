<#
.SYNOPSIS
    Vista Platform Sensor installer for Windows.

.DESCRIPTION
    Windows counterpart to install-sensor.sh. Writes the canonical sensor
    config, installs the sensor as a Windows service that starts on boot and
    restarts on failure, starts it, and waits for the sensor to register itself
    with the control plane.

    Run it from the directory that holds the sensor: crypto-sensor.exe from
    the release package, or the release file
    vista-sensor_<version>_windows_<arch>.exe as downloaded.

    Re-running it with no key (or with the key it enrolled with) on a host
    whose sensor is enrolled replaces only the binary and keeps the sensor's
    identity, configuration and certificates: that is how to upgrade it. A
    different key enrolls it afresh.

.EXAMPLE
    .\install-sensor.ps1 -Url https://vista.example.com -KeyStdin -IP 10.0.0.10 -Name sensor-dc01

    Prompts for the registration key, so it does not appear on the command
    line or in the process list. -Url is the address of your own Vista
    Platform console, as shown in your browser.

.EXAMPLE
    $env:VISTA_REGISTRATION_KEY = "REG-..."; .\install-sensor.ps1 -Url https://vista.example.com -IP 10.0.0.10

.EXAMPLE
    .\install-sensor.ps1 -Url https://vista.example.com -Key REG-xxxx -IP 10.0.0.10 -CaFingerprint 3f9a...

    For a control plane whose certificate is signed by a private CA this host
    does not trust: the sensor pins the control plane's CA only if it has this
    SHA-256 fingerprint.

.EXAMPLE
    .\install-sensor.ps1

    Upgrades an enrolled sensor in place: no key, URL or address needed.

.EXAMPLE
    .\install-sensor.ps1 -CheckDependencies

    Checks that the sensor binary runs on this host and that Npcap is
    installed, then exits. Needs neither Administrator rights nor a key.

.EXAMPLE
    .\install-sensor.ps1 -Uninstall

    Stops and deletes the service and deletes the install directory, which
    holds the configuration, certificates and private key.

.NOTES
    Must be run from an elevated (Administrator) PowerShell session, except
    with -CheckDependencies.
#>

[CmdletBinding()]
param(
    # Address of your own Vista Platform console, as shown in your browser.
    # Required on a first install; a re-run keeps the one in the config.
    [string]$Url = "",

    # Registration key minted in the console (REG-...). Required on a first
    # install, from here, -KeyStdin or VISTA_REGISTRATION_KEY. A key on the
    # command line is visible to other users in the process list; prefer the
    # other two.
    [string]$Key = "",

    # Read the registration key from standard input (the first line) when it
    # is redirected, otherwise prompt for it without echoing it.
    [switch]$KeyStdin,

    # Expected SHA-256 fingerprint of the control plane's CA certificate, for a
    # control plane whose certificate this host does not already trust.
    [string]$CaFingerprint = "",

    # IP address the operator entered when registering (parity with --ip).
    # Required on a first install; a re-run reuses the service's address.
    [string]$IP = "",

    # Human-readable sensor name. Defaults to the hostname + date.
    [string]$Name = "",

    # Comma-separated capture interfaces, each named as Windows shows the
    # adapter ("Ethernet 2", "Wi-Fi"), by its description, or by its Npcap
    # device name (\Device\NPF_{GUID}). Empty = the sensor captures on every
    # adapter that is up and has an address.
    [string]$Interfaces = "",

    # Deployment profile. Accepted but currently ignored: every sensor
    # registers and reports the datacenter_host profile.
    [string]$Profile = "datacenter_host",

    # Install location. The service binPath and -config point here.
    [string]$InstallDir = "$env:ProgramFiles\VistaSensor",

    # Check that the sensor binary runs on this host and Npcap is installed,
    # then exit.
    [switch]$CheckDependencies,

    # Stop and delete the service, and delete the install directory.
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ServiceName = "VistaSensor"
$ServiceDisplay = "Vista Platform Crypto Sensor"
$UrlHelp = "the address of your own Vista Platform console, as shown in your browser (for example -Url https://vista.example.com)"

function Write-Info  { param($m) Write-Host "[INFO]  $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err   { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }

# --- Layout ----------------------------------------------------------------
$CertsDir  = Join-Path $InstallDir "certs"
$DataDir   = Join-Path $InstallDir "data"
$ConfigPath = Join-Path $InstallDir "sensor-config.yaml"
# The sensor writes its log here when it runs as a service (stderr goes nowhere
# under the Service Control Manager); it rotates at 10 MB to sensor.log.1.
$LogFile    = Join-Path $DataDir "logs\sensor.log"
$uuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

#region sensor-binary
# The binary's name in the release package (and once installed), and the
# release's own name for the loose download.
$InstalledBinaryName = "crypto-sensor.exe"
$ReleaseBinaryPattern = "vista-sensor_*_windows_*.exe"

# The sensor binary beside this script: the name the release package uses, or
# exactly one file with the release's own name, as downloaded.
function Find-SensorBinary([string]$dir) {
    $installed = Join-Path $dir $InstalledBinaryName
    if (Test-Path -LiteralPath $installed -PathType Leaf) { return $installed }
    $released = @(Get-ChildItem -LiteralPath $dir -Filter $ReleaseBinaryPattern -File -ErrorAction SilentlyContinue)
    if ($released.Count -eq 1) { return $released[0].FullName }
    if ($released.Count -gt 1) {
        throw "Found $($released.Count) files named $ReleaseBinaryPattern in $dir ($(($released | ForEach-Object { $_.Name }) -join ', ')). Keep the one for this host (amd64 or 386), or rename it to $InstalledBinaryName."
    }
    throw "No sensor binary in $dir. Put $InstalledBinaryName (from the release package) or the downloaded $ReleaseBinaryPattern next to this script."
}
#endregion sensor-binary

#region sensor-enrollment
# Value of a top-level `key: value` line in the sensor config, quotes removed.
function Get-ConfigValue([string]$key, [string]$path = $ConfigPath) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $line = Get-Content -LiteralPath $path | Where-Object { $_ -match "^${key}:" } | Select-Object -First 1
    if (-not $line) { return $null }
    return ($line -replace "^${key}:\s*", '').Trim().Trim('"', "'")
}

function Get-KeySha256([string]$value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

# What a run does with the config at $path: 'keep' its enrolled identity,
# 'enroll' afresh, or 'needs-key' (no key, and nothing enrolled to keep).
# A host that is enrolled keeps its identity when the run brings no key or
# the key it enrolled with. Re-running the install (to upgrade the binary, or
# by mistake) must not discard the certificate and UUID the sensor holds and
# send it back to register with a key it has already spent. A different key
# means a fresh enrolment. The config records the key itself (a config written
# before the sensor stopped keeping it) or its SHA-256 fingerprint, which is
# all the sensor keeps once the platform has issued the per-sensor secret
# that replaced it (#2437).
function Get-EnrollmentDecision([string]$path, [string]$key) {
    $enrolled = (Get-ConfigValue 'sensorId' $path) -match $uuidPattern
    if ([string]::IsNullOrWhiteSpace($key)) {
        if ($enrolled) { return 'keep' }
        return 'needs-key'
    }
    if ($enrolled -and (((Get-ConfigValue 'registrationKey' $path) -eq $key) -or ((Get-ConfigValue 'registrationKeySha256' $path) -eq (Get-KeySha256 $key)))) {
        return 'keep'
    }
    return 'enroll'
}

# The fingerprint as the sensor compares it (shared/certificates): case, an
# optional sha256: prefix and separators do not matter. $null unless exactly
# 64 hexadecimal digits remain.
function ConvertTo-CaFingerprint([string]$value) {
    $normalized = ($value.Trim().ToLowerInvariant() -replace '^sha256:', '') -replace '[:\s-]', ''
    if ($normalized -notmatch '^[0-9a-f]{64}$') { return $null }
    return $normalized
}
#endregion sensor-enrollment

# True when the service exists. Get-Service exists on Windows only.
function Test-ServiceInstalled([string]$name) {
    try { return [bool](Get-Service -Name $name -ErrorAction SilentlyContinue) } catch { return $false }
}

# The address the service was installed with (SENSOR_IP_ADDRESS in its
# environment), or "".
function Get-ServiceSensorIP {
    try {
        $vars = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name Environment -ErrorAction Stop).Environment
        foreach ($v in @($vars)) { if ("$v" -like 'SENSOR_IP_ADDRESS=*') { return "$v".Substring(18) } }
    } catch { }
    return ""
}

function Assert-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Err "This installer must be run from an elevated (Administrator) PowerShell session."
        exit 1
    }
}

# Packet capture needs Npcap: the sensor loads its wpcap.dll at runtime and
# cannot capture without it. Npcap installs the DLL under System32\Npcap, and
# also into System32 itself in WinPcap API-compatible mode; the sensor loads
# either.
function Test-Npcap {
    if (-not $env:SystemRoot) { return $false }
    $wpcapCandidates = @(
        (Join-Path $env:SystemRoot "System32\Npcap\wpcap.dll"),
        (Join-Path $env:SystemRoot "System32\wpcap.dll")
    )
    return [bool]($wpcapCandidates | Where-Object { Test-Path -LiteralPath $_ })
}

#region uninstall
# -Uninstall: stops and deletes the service, then deletes the install
# directory, which holds the configuration, the certificates and the private
# key. Needs Administrator and nothing else; on a host with nothing installed
# it removes nothing and succeeds. A directory that holds no sensor install is
# left in place, so a mistyped -InstallDir cannot delete it.
function Invoke-Uninstall {
    Assert-Administrator
    $removed = 0
    if (Test-ServiceInstalled $ServiceName) {
        Write-Info "Stopping and removing the service '$ServiceName'..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Could not delete the service $ServiceName (sc.exe delete exit $LASTEXITCODE). Nothing else was removed."
            exit 1
        }
        Write-Info "Removed the service $ServiceName"
        $removed++
    }
    if (Test-Path -LiteralPath $InstallDir) {
        $ours = @($ConfigPath, (Join-Path $InstallDir $InstalledBinaryName)) | Where-Object { Test-Path -LiteralPath $_ }
        $empty = -not (Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue)
        if ($ours -or $empty) {
            # The stopped service may hold its binary for a moment longer.
            for ($i = 1; $i -le 10; $i++) {
                try { Remove-Item -LiteralPath $InstallDir -Recurse -Force; break }
                catch {
                    if ($i -eq 10) { Write-Err "Could not remove ${InstallDir}: $($_.Exception.Message)"; exit 1 }
                    Start-Sleep -Seconds 1
                }
            }
            Write-Info "Removed $InstallDir (configuration, certificates and private key)"
            $removed++
        } else {
            Write-Warn "Left $InstallDir in place: it does not hold a sensor install. Remove it by hand if it is one."
        }
    }
    if ($removed -eq 0) {
        Write-Info "Nothing to remove: the sensor is not installed on this host."
    } else {
        Write-Info "The sensor is uninstalled. It still appears in the console until you delete it there (Discovery -> Sensors & Agents)."
    }
    exit 0
}
#endregion uninstall

if ($Uninstall) { Invoke-Uninstall }

# --- Preconditions ---------------------------------------------------------

try {
    $BinarySource = Find-SensorBinary $PSScriptRoot
} catch {
    Write-Err $_.Exception.Message
    exit 1
}

# The version the platform shows is the one stamped into this binary - the
# sensor reports it itself at registration and on every heartbeat.
# Display only: an unreadable version leaves "unknown" and changes nothing.
$SensorVersion = "unknown"
$versionRan = $false
try {
    $versionOutput = @(& $BinarySource --version 2>$null)
    $versionRan = ($LASTEXITCODE -eq 0)
    if ($versionOutput.Count -gt 0 -and "$($versionOutput[0])" -match ' v(\S+)$') { $SensorVersion = $Matches[1] }
} catch { }

if ($CheckDependencies) {
    $ok = $true
    if ($versionRan) {
        Write-Info "Sensor v$SensorVersion runs on this host."
    } else {
        Write-Err "The sensor ($BinarySource) cannot run on this host. Check that it is the Windows build for this host's architecture (amd64 or 386)."
        $ok = $false
    }
    if (Test-Npcap) {
        Write-Info "Npcap is installed (wpcap.dll found)."
    } else {
        Write-Err "Npcap is not installed; the sensor needs it to capture packets. Install it from https://npcap.com/#download (keep 'WinPcap API-compatible Mode' checked)."
        $ok = $false
    }
    if ($ok) { exit 0 }
    exit 1
}

# The key, from -Key, -KeyStdin or the environment, and the CA fingerprint,
# checked before anything on the host changes.
if ($KeyStdin) {
    if ([Console]::IsInputRedirected) {
        $Key = [Console]::In.ReadLine()
    } else {
        $secure = Read-Host -AsSecureString "Registration key"
        $Key = [System.Net.NetworkCredential]::new("", $secure).Password
    }
}
if ([string]::IsNullOrEmpty($Key) -and $env:VISTA_REGISTRATION_KEY) { $Key = $env:VISTA_REGISTRATION_KEY }
if ($null -ne $Key) { $Key = $Key.Trim() }
# A host with an install may be enrolled already and need no key, URL or
# address; whether it is enrolled is read as Administrator below.
$existingInstall = (Test-Path -LiteralPath $ConfigPath) -or (Test-ServiceInstalled $ServiceName)
if ([string]::IsNullOrWhiteSpace($Key) -and -not $existingInstall) {
    Write-Err "A registration key is required: -Key, -KeyStdin, or VISTA_REGISTRATION_KEY in the environment."
    exit 1
}
if ([string]::IsNullOrWhiteSpace($Url) -and -not $existingInstall) {
    Write-Err "-Url is required: $UrlHelp."
    exit 1
}
if ([string]::IsNullOrWhiteSpace($IP) -and -not $existingInstall) {
    Write-Err "-IP is required on a first install: the address of this host that the registration key was created for."
    exit 1
}
if ($CaFingerprint) {
    $normalized = ConvertTo-CaFingerprint $CaFingerprint
    if (-not $normalized) {
        Write-Err "-CaFingerprint must be a SHA-256 fingerprint: 64 hexadecimal characters (upper or lower case; colons and a sha256: prefix allowed)."
        exit 1
    }
    $CaFingerprint = $normalized
}

# After the argument checks, so a mistake is reported without elevation.
Assert-Administrator

# Nothing has changed yet. Without a key, only an enrolled host can go on, and
# it keeps the platform, the address and the identity it has.
$decision = Get-EnrollmentDecision $ConfigPath $Key
if ($decision -eq 'needs-key') {
    Write-Err "A registration key is required: $ConfigPath does not record an enrolled sensor."
    exit 1
}
$keepEnrolment = ($decision -eq 'keep')
$configuredUrl = Get-ConfigValue 'controlPlaneUrl'
if ($keepEnrolment -and $configuredUrl) { $Url = $configuredUrl }
if ([string]::IsNullOrWhiteSpace($Url)) { $Url = $configuredUrl }
if ([string]::IsNullOrWhiteSpace($Url)) {
    Write-Err "-Url is required: $ConfigPath does not record a platform. It is $UrlHelp."
    exit 1
}
if ([string]::IsNullOrWhiteSpace($IP)) { $IP = Get-ServiceSensorIP }
if ([string]::IsNullOrWhiteSpace($IP)) {
    Write-Err "-IP is required: the service does not record the address of this host that the registration key was created for."
    exit 1
}

# Check before touching the service or config, so a missing runtime fails here
# with instructions rather than as a sensor that starts and captures nothing.
if (-not (Test-Npcap)) {
    Write-Err "Npcap is not installed; the sensor needs it to capture packets."
    Write-Err "Install it from https://npcap.com/#download (keep 'WinPcap API-compatible Mode' checked), then re-run this installer."
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Name)) {
    $Name = "sensor-$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd')"
}

Write-Host ""
Write-Host "Vista Platform Sensor Installer (Windows)" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Info "Sensor version: $SensorVersion"
Write-Info "Control plane : $Url"
Write-Info "Sensor name   : $Name"
Write-Info "IP address    : $IP"
Write-Info "Profile       : $Profile"
Write-Info "Install dir   : $InstallDir"
if ($CaFingerprint) { Write-Info "CA fingerprint: $CaFingerprint" }
Write-Host ""
if ($Profile -ne "datacenter_host") {
    Write-Warn "-Profile $Profile is not applied yet: the sensor registers itself and reports the datacenter_host profile."
}

if ($keepEnrolment) {
    Write-Info "This host is already enrolled (sensor $(Get-ConfigValue 'sensorId')); keeping its identity and configuration."
}

# Stop a previous install so it cannot rewrite the config while we replace it.
# Best effort: a service that will not stop keeps its binary locked, and the
# Copy-Item below then fails loudly.
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null

# --- Administrators and SYSTEM only ----------------------------------------
# The configuration holds the registration key until the sensor redeems it,
# and the certs directories hold the sensor's private key. Program Files lets
# every user read what is under it, and the sensor rewrites its config, so the
# protection is on the directory: inherited by everything created in it, then
# reset onto anything an earlier install left. SIDs, not names, so it works on
# a localised Windows: S-1-5-18 is SYSTEM, S-1-5-32-544 Administrators.
& icacls.exe $InstallDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /Q | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Err "Could not restrict $InstallDir to Administrators and SYSTEM (icacls exit $LASTEXITCODE). Nothing was written."
    exit 1
}
if (Get-ChildItem -LiteralPath $InstallDir -Force) {
    & icacls.exe (Join-Path $InstallDir "*") /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Could not reset the permissions under $InstallDir (icacls exit $LASTEXITCODE). Nothing was written."
        exit 1
    }
}

# Earlier versions of this installer registered on the sensor's behalf and wrote
# a control-plane-generated private key to certs\. That identity was never usable
# by the sensor; do not leave its key on disk. A fresh enrolment also must not
# inherit the previous sensor's certificate.
if (-not $keepEnrolment) {
    foreach ($stale in @($CertsDir, (Join-Path $DataDir "certs"))) {
        if (Test-Path $stale) { Remove-Item -Recurse -Force $stale }
    }
}

Write-Info "Installing sensor binary..."
Copy-Item -Force -LiteralPath $BinarySource -Destination (Join-Path $InstallDir $InstalledBinaryName)

# --- Write the canonical sensor config ------------------------------------
# The installer does NOT register the sensor. The sensor registers itself on
# first start: it generates its keypair locally (the private key never leaves
# the host), sends a CSR with its build-stamped version and capabilities, then
# rewrites this file with the UUID the platform accepted and the paths of the
# certificate it was issued. Registering here instead spent the single-use key
# before the sensor could use it and recorded a made-up version.
#
# sensorId carries the sensor NAME until registration: the loader uses a
# non-UUID sensorId as the registration name. Flat camelCase keys - the schema
# sensor/internal/config.ConfigFile parses (nested control_plane:/url: is NOT
# read).
if (-not $keepEnrolment) {
    Write-Info "Writing configuration to $ConfigPath"

    # Single-quoted YAML scalars take backslashes literally; a quote is doubled.
    function ConvertTo-YamlScalar([string]$v) { "'" + $v.Replace("'", "''") + "'" }

    $interfaceList = @()
    if (-not [string]::IsNullOrWhiteSpace($Interfaces)) {
        $interfaceList = $Interfaces.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
    $ifaceYaml = "[" + (($interfaceList | ForEach-Object { ConvertTo-YamlScalar $_ }) -join ", ") + "]"

    $configContent = @"
# Vista Platform Sensor configuration (generated by install-sensor.ps1)
# sensorId holds the sensor's name until it registers, then its UUID.
sensorId: $(ConvertTo-YamlScalar $Name)
controlPlaneUrl: $(ConvertTo-YamlScalar $Url)
registrationKey: $(ConvertTo-YamlScalar $Key)
reportingIntervalSeconds: 30

capture:
  interfaces: $ifaceYaml
  activeProbing: true
  networkDiscovery: true

storage:
  dataPath: $(ConvertTo-YamlScalar $DataDir)
"@
    # UTF-8 without a BOM (Windows PowerShell's Out-File -Encoding utf8 adds one).
    [System.IO.File]::WriteAllText($ConfigPath, $configContent, (New-Object System.Text.UTF8Encoding $false))
}

#region service-config
# Points the service at $PathName and makes it start on boot, then reads both
# back and throws unless they took. Windows PowerShell 5.1 mangles the quotes
# embedded in an argument to a native program, so the
# `sc.exe config <name> binPath= "<path with quotes>"` this replaced printed its
# usage text and changed nothing, unnoticed: a re-run never re-enabled a
# service the installer had disabled, and a new command line never reached an
# existing service. Win32_Service.Change takes the path as data, not as a
# command line. $Get and $Change stand in for Win32_Service in tests
# (scripts/install-*-ps1 tests); the read-back is what makes a no-op fail.
function Set-ServiceStartup {
    param(
        [string]$Name,
        [string]$PathName,
        [scriptblock]$Get = { param($n) Get-CimInstance -ClassName Win32_Service -Filter "Name='$n'" },
        [scriptblock]$Change = {
            param($svc, $path)
            (Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{ PathName = $path; StartMode = 'Automatic' }).ReturnValue
        }
    )
    $svc = & $Get $Name
    if (-not $svc) { throw "Service $Name does not exist." }
    $rc = & $Change $svc $PathName
    if ($rc -ne 0) { throw "Could not reconfigure service ${Name}: Win32_Service.Change returned $rc." }
    $after = & $Get $Name
    if ("$($after.PathName)" -ne $PathName -or "$($after.StartMode)" -ne 'Auto') {
        throw "Service $Name was not reconfigured: it runs '$($after.PathName)' and starts '$($after.StartMode)'; the installer set '$PathName' and Auto."
    }
}
#endregion service-config

# --- Install + start the Windows service ----------------------------------
# Auto-start (survives reboot / maintenance) + restart-on-failure = the Windows
# equivalent of systemd `WantedBy=multi-user.target` + `Restart=always`.
Write-Info "Installing Windows service '$ServiceName'..."
$binPath = "`"$InstallDir\crypto-sensor.exe`" --verbose -config `"$ConfigPath`""
if ($CaFingerprint) {
    # Pins the control plane's CA on first start, verified against this
    # fingerprint; ignored once a CA is in the config.
    $binPath += " -ca-fingerprint $CaFingerprint"
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Warn "Service already exists - reconfiguring."
} else {
    # A cmdlet, not a native command: it takes the path as data and throws
    # (ErrorActionPreference Stop) if it cannot create the service.
    New-Service -Name $ServiceName -DisplayName $ServiceDisplay `
        -BinaryPathName $binPath -StartupType Automatic `
        -Description "Vista Platform passive crypto-discovery sensor" | Out-Null
}
# Both paths: an existing service may be Disabled (this installer disables it
# on a rejected key or a sensor that cannot capture) or run an older command
# line; a new one is read back too.
try {
    Set-ServiceStartup $ServiceName $binPath
} catch {
    Write-Err "Could not configure the service: $($_.Exception.Message)"
    exit 1
}

# Restart on crash: reset failure count daily, restart after 10s on each of the
# first three failures (the SCM repeats the last action for any later one).
# Neither argument list has a quote for Windows PowerShell 5.1 to mangle, but
# each exit status is checked: without these the sensor stays down.
sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/10000/restart/10000 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Err "Could not set the service's restart-on-failure actions (sc.exe failure exit $LASTEXITCODE)."
    exit 1
}
# Also restart when the sensor stops itself with a failure exit code: that is
# how it honours a restart command from the control plane. Without this flag
# the SCM only acts on a crash, and the sensor would stay stopped.
sc.exe failureflag $ServiceName 1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Err "Could not make the service restart after a failure exit (sc.exe failureflag exit $LASTEXITCODE)."
    exit 1
}

# The address the operator entered when creating the registration key (-IP).
# Pinning it makes registration report the address the platform expects even on
# a multi-homed host, where the sensor's own guess can differ. Service-scoped
# environment lives in the service's registry key.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" `
    -Name Environment -Type MultiString -Value @("SENSOR_IP_ADDRESS=$IP")

# Log lines this start wrote: everything past the log's current end. The
# sensor keeps the file open, so share it for writing and for its rotation.
$logStartOffset = 0
if (Test-Path $LogFile) { $logStartOffset = (Get-Item $LogFile).Length }
function Get-NewLogText {
    if (-not (Test-Path $LogFile)) { return "" }
    try {
        $stream = [System.IO.File]::Open($LogFile, 'Open', 'Read', 'ReadWrite, Delete')
        try {
            # A rotation since we started means the whole current file is new.
            if ($stream.Length -ge $logStartOffset) { [void]$stream.Seek($logStartOffset, 'Begin') }
            $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            return $reader.ReadToEnd()
        } finally { $stream.Dispose() }
    } catch { return "" }
}

Write-Info "Starting service..."
# The sensor reports Running once it has registered (or begun retrying) and
# started capturing. A sensor that exits during startup (a rejected
# registration key does) makes Start-Service throw; the log says why, so carry
# on to the checks below instead of stopping at the exception.
$startError = $null
try {
    Start-Service -Name $ServiceName
} catch {
    $startError = $_.Exception.Message
}

# --- Wait for the sensor to register itself --------------------------------
# Registration is confirmed only by the sensor: it rewrites sensorId with the
# UUID the platform accepted. A running service is not a registered sensor - an
# unregistered one captures traffic and can submit none of it.
$timeoutSeconds = 90
Write-Info "Waiting up to ${timeoutSeconds}s for the sensor to register..."
$sensorId = $null
$rejected = $false
$cannotCapture = $false
$deadline = (Get-Date).AddSeconds($timeoutSeconds)
while ((Get-Date) -lt $deadline) {
    $value = Get-ConfigValue 'sensorId'
    if ($value -match $uuidPattern) { $sensorId = $value; break }
    $newLog = Get-NewLogText
    if ($newLog -match 'Registration was REJECTED') { $rejected = $true; break }
    # The sensor checks that it can capture before it registers, and stops
    # with the key unused when it cannot.
    if ($newLog -match 'Not registering: the registration key is unused') { $cannotCapture = $true; break }
    Start-Sleep -Seconds 2
}

$svc = Get-Service -Name $ServiceName
if (-not $sensorId) {
    Write-Host ""
    # The sensor marks failures with these emoji. Built from code points: this
    # file has no BOM, so Windows PowerShell reads it as ANSI, not UTF-8.
    $failureMarks = "$([char]::ConvertFromUtf32(0x26D4))|$([char]::ConvertFromUtf32(0x274C))|Registration (FAILED|retry failed)|Failed to start capture on interface"
    (Get-NewLogText) -split "`r?`n" | Where-Object { $_ -match $failureMarks } |
        Select-Object -Last 8 | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
    if ($rejected) {
        # A rejected key never succeeds; stop the service rather than leave the
        # SCM restarting it every 10 seconds.
        # Disable first so a restart the SCM has already queued cannot start it.
        # Best effort: the install has already failed and says so; a re-run
        # re-enables it (Set-ServiceStartup).
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Write-Err "The control plane REJECTED the registration key (see above): it is invalid, expired, or already used."
        Write-Err "Generate a new key (Discovery -> Sensors & Agents -> Register) and re-run this installer with it."
        Write-Info "The sensor service has been stopped and disabled."
    } elseif ($cannotCapture) {
        # Retrying cannot help until the interfaces change; the key is still
        # good, so re-running the installer with -Interfaces is the fix.
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Write-Err "The sensor cannot capture on this host (see above), so it did not register: the registration key was NOT used."
        Write-Err "Re-run this installer with -Interfaces naming an adapter from the list above (for example -Interfaces `"Ethernet`")."
        Write-Info "The sensor service has been stopped and disabled."
    } else {
        if ($startError) { Write-Err "Starting the service failed: $startError" }
        Write-Err "The sensor did not register within ${timeoutSeconds}s (service status: $($svc.Status))."
        Write-Err "Check that $Url is reachable from this host."
        Write-Info "Log: $LogFile"
    }
    exit 1
}
if ($svc.Status -ne 'Running') {
    Write-Err "The sensor registered but the service is not running (status: $($svc.Status))."
    Write-Info "Log: $LogFile"
    exit 1
}

Write-Host ""
Write-Info "Sensor registered and running."
Write-Info "Sensor ID     : $sensorId"
Write-Info "Sensor version: $SensorVersion"
Write-Host ""
Write-Host "Management:" -ForegroundColor Cyan
Write-Host "  Status:  Get-Service $ServiceName"
Write-Host "  Logs:    Get-Content -Tail 50 -Wait '$LogFile'"
Write-Host "  Events:  Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='$ServiceName'} -MaxEvents 20"
Write-Host "  Stop:    Stop-Service $ServiceName"
Write-Host "  Restart: Restart-Service $ServiceName"
Write-Host "  Uninstall: & '$PSCommandPath' -Uninstall"
