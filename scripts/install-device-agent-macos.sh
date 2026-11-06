#!/bin/bash

# Vista Platform Device Agent installer for macOS (launchd).
#
# Installs the device agent as a LaunchDaemon that starts at boot and restarts
# when it stops, writes its configuration, starts it, and waits for the agent to
# enroll itself with the platform. The macOS counterpart of
# install-device-agent.sh: the same options, the same output, the same
# re-run-to-upgrade behaviour.
#
# Usage: sudo bash install-device-agent-macos.sh --url URL --key-stdin [options]
#
# Written for the bash macOS ships (3.2): no associative arrays, no ${v,,}, no
# GNU-only tools. scripts/install-macos.test.mjs holds it to that.

set -e

CONTROL_PLANE_URL=""
# The key may come from the environment so it stays out of the process list.
REGISTRATION_KEY="${VISTA_REGISTRATION_KEY:-}"
CA_FINGERPRINT=""
CHECK_DEPENDENCIES=false
UNINSTALL=false
REGISTRATION_TIMEOUT=${REGISTRATION_TIMEOUT:-90}

# Where things go. No earlier install exists on macOS, so these use the
# product's names.
INSTALL_DIR="/usr/local/vista-device-agent"
LABEL="io.vistasecurity.device-agent"
LAUNCHD_DIR="/Library/LaunchDaemons"
LOG_DIR="/Library/Logs/Vista/device-agent"
EXECUTABLE="vista-device-agent"
# A hidden system account (macOS names those with a leading underscore): the
# agent talks to devices over ordinary sockets and needs no root.
SERVICE_USER="_vistadeviceagent"
# The names the downloaded binary may have: the archive's, then the loose
# release file's (<prefix>_<version>_darwin_<arch>).
ARCHIVE_NAME="device-agent"
RELEASE_PREFIX="vista-device-agent"
AGENT_TITLE="Device agent"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
print_header()  { echo -e "${BLUE}$1${NC}"; }

# --- shared macOS installer functions (begin) ---
# install-sensor-macos.sh and install-device-agent-macos.sh carry this block
# byte for byte; scripts/install-macos.test.mjs fails when they differ.

# Shows only the last 4 characters of a registration key, for any output.
mask_key() {
    local k=$1
    if [[ ${#k} -le 4 ]]; then
        printf '****'
    else
        printf '****%s' "${k: -4}"
    fi
}

# Reads the registration key from the first line of stdin (--key-stdin), so it
# never appears in the process list.
read_key_from_stdin() {
    local line=""
    IFS= read -r line || true
    REGISTRATION_KEY=${line%$'\r'}
}

# Double-quoted YAML scalar: a "#" or ": " in a value cannot break the file.
yaml_quote() {
    local s=${1//\\/\\\\}
    s=${s//\"/\\\"}
    printf '"%s"' "$s"
}

# Text for a plist <string>. sed, not ${s//&/...}: bash 5.2 reads an & in
# the replacement as the matched text (patsub_replacement), bash 3.2 does not.
xml_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# Prints the value of a top-level `key: value` line in an agent config, with
# optional surrounding double quotes removed.
read_config_value() {
    sed -n "s/^$1:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*\$/\1/p" "$2" 2>/dev/null | head -1
}

# Prints the SHA-256 (hex) of its argument. macOS has shasum, not sha256sum.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | cut -d' ' -f1
    else
        printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
    fi
}

# This Mac's architecture as release files name it. A shell running under
# Rosetta reports x86_64 on Apple silicon, so ask the hardware.
macos_arch() {
    if [[ "$(sysctl -n hw.optional.arm64 2>/dev/null)" == "1" ]]; then
        echo arm64
        return 0
    fi
    case "$(uname -m)" in
        arm64|aarch64) echo arm64 ;;
        x86_64|amd64) echo amd64 ;;
        *) uname -m ;;
    esac
}

# Prints the path of the agent binary to install: ./$ARCHIVE_NAME (the name in
# the release archive), else the one loose release file for this Mac,
# ./$RELEASE_PREFIX_<version>_darwin_<arch>. Fails, naming both, otherwise.
find_agent_binary() {
    local arch f found="" count=0
    if [[ -f "./$ARCHIVE_NAME" ]]; then
        echo "./$ARCHIVE_NAME"
        return 0
    fi
    arch=$(macos_arch)
    for f in ./"${RELEASE_PREFIX}"_*_darwin_"${arch}"; do
        [[ -f "$f" ]] || continue
        found=$f
        count=$((count + 1))
    done
    if [[ $count -eq 1 ]]; then
        echo "$found"
        return 0
    fi
    if [[ $count -gt 1 ]]; then
        print_error "Several ${RELEASE_PREFIX}_<version>_darwin_${arch} files are in the current directory; keep only the one to install." >&2
        return 1
    fi
    print_error "$AGENT_TITLE binary not found in the current directory." >&2
    print_error "Download and verify the macOS build for this Mac's architecture ($arch), and place it here either as ./$ARCHIVE_NAME (its name in the .tar.gz archive) or under its release name ${RELEASE_PREFIX}_<version>_darwin_${arch}." >&2
    return 1
}

# Runs the binary's -version from a private copy without the download
# quarantine flag (Gatekeeper refuses to run a quarantined binary that is not
# notarized). Nothing on the host changes; no root needed. Sets AGENT_VERSION
# to the version the binary reports.
check_binary_runs() {
    local binary=$1 tmp output status=0
    AGENT_VERSION=""
    if [[ ! -x "$binary" ]]; then
        print_error "The $AGENT_TITLE binary is not executable. Run: chmod +x $binary"
        return 1
    fi
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/vista-check.XXXXXX")
    cp "$binary" "$tmp/agent"
    xattr -d com.apple.quarantine "$tmp/agent" 2>/dev/null || true
    output=$(cd "$tmp" && LC_ALL=C ./agent -version 2>&1) || status=$?
    rm -rf "$tmp"
    if [[ $status -eq 0 ]]; then
        AGENT_VERSION=$(printf '%s\n' "$output" | head -1 | sed -n 's/.* v\([^ ]*\)$/\1/p')
        return 0
    fi
    print_error "The $AGENT_TITLE cannot run on this Mac. Installation stopped before anything was changed."
    printf '%s\n' "$output"
    print_error "Check that the file is the macOS build for this Mac's architecture ($(macos_arch))."
    return 1
}

# Writes the program launchd runs: it starts the agent, keeps its output in a
# log that cannot fill the disk, and turns the agent's exit status into one
# launchd can act on.
write_service_wrapper() {
    cat > "$1" << 'WRAPPER'
#!/bin/bash
# Runs a Vista Platform agent under launchd. Written by the macOS installer.
#
#   service.sh LOG_FILE PROGRAM [ARGUMENT...]
#
# launchd decides whether to start a job again from its exit status alone, and
# has nothing like systemd's RestartPreventExitStatus. The agents exit 78
# (EX_CONFIG) when only a person can fix the start (a rejected registration
# key, an unusable config) and exit 0 when the platform asks them to restart.
# The job's plist sets KeepAlive SuccessfulExit=false, so this reports 78 as
# success (launchd leaves the job stopped until the next boot or install) and
# any other end as a failure (launchd starts it again after ThrottleInterval).
#
# The agent's output goes to LOG_FILE, which moves to LOG_FILE.1 once it passes
# VISTA_LOG_MAX_BYTES (default 10 MiB): two files at most.
log_file=$1
shift
max_bytes=${VISTA_LOG_MAX_BYTES:-10485760}
pipe="$log_file.pipe"
program=${1##*/}

copy_to_log() {
    local line size=0
    LC_ALL=C
    if [ -f "$log_file" ]; then
        size=$(wc -c < "$log_file" | tr -d ' ')
    fi
    exec 3>>"$log_file"
    while IFS= read -r line || [ -n "$line" ]; do
        printf '%s\n' "$line" >&3
        size=$((size + ${#line} + 1))
        if [ "$size" -ge "$max_bytes" ]; then
            exec 3>&-
            mv -f "$log_file" "$log_file.1"
            exec 3>>"$log_file"
            size=0
        fi
    done
    exec 3>&-
}

say() {
    printf '%s vista-service: %s\n' "$(date '+%Y/%m/%d %H:%M:%S')" "$*" >&4
}

rm -f "$pipe"
mkfifo -m 600 "$pipe" || exit 1
copy_to_log < "$pipe" &
copier=$!
exec 4>"$pipe"

"$@" >&4 2>&4 &
child=$!
trap 'kill -TERM "$child" 2>/dev/null' TERM INT HUP
wait "$child"
status=$?
# A signal interrupts wait; the second wait collects the agent's own status.
while kill -0 "$child" 2>/dev/null; do
    wait "$child"
    status=$?
done

case $status in
    78)
        say "$program exited with status 78: it needs a person (see the lines above). launchd will not start it again until the next boot; fix the cause and run the installer again."
        result=0
        ;;
    0)
        say "$program exited normally; launchd starts it again unless the job is being stopped."
        result=75
        ;;
    *)
        say "$program exited with status $status; launchd starts it again unless the job is being stopped."
        result=$status
        ;;
esac
exec 4>&-
# Anything the agent started and left running still holds the log open; the
# copier gets five seconds, and launchd ends the rest when this exits.
( sleep 5; kill "$copier" 2>/dev/null ) &
timer=$!
wait "$copier"
kill "$timer" 2>/dev/null
rm -f "$pipe"
exit "$result"
WRAPPER
    chmod 755 "$1"
}

# write_launchd_plist FILE LABEL USER WORKDIR STDERR_LOG PROGRAM [ARGUMENT...]
#
# A LaunchDaemon that starts at boot and is started again whenever its program
# exits unsuccessfully (see write_service_wrapper for what that means), at most
# every 10 seconds. USER empty: the job runs as root. Environment variables come
# from the array PLIST_ENV, as NAME=value.
write_launchd_plist() {
    local file=$1 label=$2 user=$3 workdir=$4 stderr_log=$5 arg kv
    shift 5
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        echo '<plist version="1.0">'
        echo '<dict>'
        printf '  <key>Label</key>\n  <string>%s</string>\n' "$(xml_escape "$label")"
        echo '  <key>ProgramArguments</key>'
        echo '  <array>'
        for arg in "$@"; do
            printf '    <string>%s</string>\n' "$(xml_escape "$arg")"
        done
        echo '  </array>'
        if [[ -n "$user" ]]; then
            printf '  <key>UserName</key>\n  <string>%s</string>\n' "$(xml_escape "$user")"
            printf '  <key>GroupName</key>\n  <string>%s</string>\n' "$(xml_escape "$user")"
        fi
        printf '  <key>WorkingDirectory</key>\n  <string>%s</string>\n' "$(xml_escape "$workdir")"
        echo '  <key>RunAtLoad</key>'
        echo '  <true/>'
        echo '  <key>KeepAlive</key>'
        echo '  <dict>'
        echo '    <key>SuccessfulExit</key>'
        echo '    <false/>'
        echo '  </dict>'
        echo '  <key>ThrottleInterval</key>'
        echo '  <integer>10</integer>'
        printf '  <key>StandardOutPath</key>\n  <string>%s</string>\n' "$(xml_escape "$stderr_log")"
        printf '  <key>StandardErrorPath</key>\n  <string>%s</string>\n' "$(xml_escape "$stderr_log")"
        if [[ ${#PLIST_ENV[@]} -gt 0 ]]; then
            echo '  <key>EnvironmentVariables</key>'
            echo '  <dict>'
            for kv in "${PLIST_ENV[@]}"; do
                printf '    <key>%s</key>\n    <string>%s</string>\n' "$(xml_escape "${kv%%=*}")" "$(xml_escape "${kv#*=}")"
            done
            echo '  </dict>'
        fi
        echo '</dict>'
        echo '</plist>'
    } > "$file"
}

# True while launchd has the job loaded.
job_loaded() {
    launchctl print "system/$1" >/dev/null 2>&1
}

# True while the job's process runs.
job_running() {
    launchctl print "system/$1" 2>/dev/null | grep -q 'state = running'
}

# Stops and unloads the job, and waits until launchd has let it go: a job
# that is still being torn down refuses a new bootstrap.
stop_job() {
    local label=$1 plist=$2 i=0
    job_loaded "$label" || return 0
    launchctl bootout "system/$label" 2>/dev/null || launchctl unload "$plist" 2>/dev/null || true
    while job_loaded "$label" && [[ $i -lt 30 ]]; do
        sleep 1
        i=$((i + 1))
    done
}

# Loads and starts the job. A disabled job (the installer disables it after a
# rejected key) is enabled first.
start_job() {
    local label=$1 plist=$2 i=0
    launchctl enable "system/$label" 2>/dev/null || true
    until launchctl bootstrap system "$plist" 2>/dev/null; do
        i=$((i + 1))
        if [[ $i -ge 5 ]]; then
            launchctl bootstrap system "$plist"
            return $?
        fi
        sleep 2
    done
}

# Prints what was appended to file $1 after its first $2 bytes.
log_since() {
    [[ -f "$1" ]] || return 0
    tail -c +$(($2 + 1)) "$1" 2>/dev/null || true
}

# The size of file $1 in bytes, 0 when it does not exist.
size_of() {
    if [[ -f "$1" ]]; then
        wc -c < "$1" | tr -d ' '
    else
        echo 0
    fi
}

# Prints the most useful part of a failed start: the lines the agent marks as
# errors, else the last lines it wrote.
show_log_tail() {
    local text
    text=$(log_since "$1" "$2")
    if printf '%s\n' "$text" | grep -q -E '⛔|❌'; then
        printf '%s\n' "$text" | grep -E '⛔|❌|exited with status' | tail -8
    else
        printf '%s\n' "$text" | tail -20
    fi
}
# --- shared macOS installer functions (end) ---

show_usage() {
    cat << EOF
Vista Platform Device Agent Installer for macOS
===============================================

Usage: sudo bash $0 --url URL --key-stdin [options]

Options:
    -u, --url URL              Platform URL, as shown in the console (required)
    -k, --key KEY              Registration key (required). A key on the command line is
                               visible to other users in the process list; prefer one of:
    --key-stdin                Read the key from the first line of standard input
                               (VISTA_REGISTRATION_KEY=... in the environment also works)
    --ca-fingerprint SHA256    Expected SHA-256 fingerprint of the platform's CA, for a
                               platform whose certificate this Mac does not already trust
    -d, --dir DIRECTORY        Installation directory (default: $INSTALL_DIR)
    --check-dependencies       Check the device agent binary runs on this Mac, then exit (no root needed)
    --uninstall                Stop the agent and remove it, its configuration, its logs
                               and its service account
    -h, --help                 Show this help

Run it from the directory holding the downloaded agent: the contents of the
macOS .tar.gz archive, or the loose ${RELEASE_PREFIX}_<version>_darwin_<arch> file.
Re-running it with the same key keeps the agent's enrollment and replaces only
the binary, which is how to upgrade it.

The agent runs as the hidden system account $SERVICE_USER, not as root.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url) CONTROL_PLANE_URL="$2"; shift 2 ;;
            -k|--key) REGISTRATION_KEY="$2"; shift 2 ;;
            --key-stdin) read_key_from_stdin; shift ;;
            --ca-fingerprint) CA_FINGERPRINT="$2"; shift 2 ;;
            -d|--dir) INSTALL_DIR="$2"; shift 2 ;;
            --check-dependencies) CHECK_DEPENDENCIES=true; shift ;;
            --uninstall) UNINSTALL=true; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) print_error "Unknown option: $1"; show_usage; exit 1 ;;
        esac
    done
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# The highest ID from 499 down to 300 that no user and no group has. macOS
# keeps IDs below 500 for system accounts, and its own sit low in that range.
free_system_id() {
    local used id=499
    used=" $( { dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } 2>/dev/null | awk '{ printf "%s ", $2 }')"
    while [[ $id -ge 300 ]]; do
        case "$used" in
            *" $id "*) ;;
            *) echo "$id"; return 0 ;;
        esac
        id=$((id - 1))
    done
    return 1
}

# Creates the hidden service account and its group unless they exist: no
# password, no shell, no home, not shown at the login window.
ensure_service_account() {
    local id gid
    if dscl . -read "/Users/$SERVICE_USER" UniqueID >/dev/null 2>&1; then
        print_status "Service account $SERVICE_USER already exists"
        return 0
    fi
    print_status "Creating service account: $SERVICE_USER"
    if ! id=$(free_system_id); then
        print_error "No free system user ID between 300 and 499 for $SERVICE_USER"
        exit 1
    fi
    if dscl . -read "/Groups/$SERVICE_USER" PrimaryGroupID >/dev/null 2>&1; then
        gid=$(dscl . -read "/Groups/$SERVICE_USER" PrimaryGroupID | awk '{ print $2 }')
    else
        gid=$id
        dscl . -create "/Groups/$SERVICE_USER"
        dscl . -create "/Groups/$SERVICE_USER" PrimaryGroupID "$gid"
        dscl . -create "/Groups/$SERVICE_USER" RealName "Vista Platform Device Agent"
        dscl . -create "/Groups/$SERVICE_USER" Password '*'
    fi
    dscl . -create "/Users/$SERVICE_USER"
    dscl . -create "/Users/$SERVICE_USER" UniqueID "$id"
    dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID "$gid"
    dscl . -create "/Users/$SERVICE_USER" RealName "Vista Platform Device Agent"
    dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
    dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
    dscl . -create "/Users/$SERVICE_USER" Password '*'
    dscl . -create "/Users/$SERVICE_USER" IsHidden 1
}

uninstall() {
    require_root
    local plist="$LAUNCHD_DIR/$LABEL.plist"
    print_status "Stopping and removing the device agent ($LABEL)..."
    stop_job "$LABEL" "$plist"
    rm -f "$plist"
    rm -rf "$INSTALL_DIR" "$LOG_DIR"
    if dscl . -read "/Users/$SERVICE_USER" UniqueID >/dev/null 2>&1; then
        dscl . -delete "/Users/$SERVICE_USER" || true
    fi
    if dscl . -read "/Groups/$SERVICE_USER" PrimaryGroupID >/dev/null 2>&1; then
        dscl . -delete "/Groups/$SERVICE_USER" || true
    fi
    print_status "Removed $plist, $INSTALL_DIR, $LOG_DIR and the account $SERVICE_USER."
    print_status "The agent still appears in the console until you delete it there (Discovery → Sensors & Agents)."
}

main() {
    parse_args "$@"

    if [[ "$(uname -s)" != Darwin ]]; then
        print_error "This installer is for macOS. On Linux use install-device-agent.sh; on Windows use install-device-agent.ps1."
        exit 1
    fi

    if [[ "$UNINSTALL" == "true" ]]; then
        uninstall
        exit 0
    fi

    local binary
    binary=$(find_agent_binary) || exit 1
    check_binary_runs "$binary" || exit 1
    print_status "Device agent runs on this Mac ($binary)."
    if [[ "$CHECK_DEPENDENCIES" == "true" ]]; then
        exit 0
    fi

    if [[ -z "$CONTROL_PLANE_URL" || -z "$REGISTRATION_KEY" ]]; then
        print_error "--url and --key are required"
        show_usage
        exit 1
    fi
    if [[ -n "$CA_FINGERPRINT" && ! "$CA_FINGERPRINT" =~ ^[0-9A-Fa-f:]+$ ]]; then
        print_error "--ca-fingerprint must be the SHA-256 fingerprint in hexadecimal (colons allowed)"
        exit 1
    fi
    require_root

    local version=$AGENT_VERSION
    print_header "🚀 Vista Platform Device Agent Installer (macOS)"
    echo "=================================================="
    echo "  Agent Version: ${version:-unknown}"
    echo "  Platform: $CONTROL_PLANE_URL"
    echo "  Install Directory: $INSTALL_DIR"

    local plist="$LAUNCHD_DIR/$LABEL.plist"
    local CONFIG_FILE="$INSTALL_DIR/etc/device-agent.yaml"
    local wrapper="$INSTALL_DIR/service.sh"
    local log_file="$LOG_DIR/device-agent.log"
    local uuid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

    # A Mac this key already enrolled keeps its identity. Re-running the same
    # install command (to upgrade the binary, or by mistake) must not discard
    # the certificate and agent ID and send it back to register with a key it
    # has already spent. A different key means a fresh enrollment. The config
    # keeps the key itself until the platform issues the agent its own secret,
    # then only the key's SHA-256.
    local keep_enrollment=false current_id
    current_id=$(read_config_value agent_id "$CONFIG_FILE")
    if [[ -f "$CONFIG_FILE" && "$current_id" =~ $uuid_re ]] \
        && { [[ "$(read_config_value registration_key "$CONFIG_FILE")" == "$REGISTRATION_KEY" ]] \
            || [[ "$(read_config_value registration_key_sha256 "$CONFIG_FILE")" == "$(sha256_of "$REGISTRATION_KEY")" ]]; }; then
        keep_enrollment=true
        print_status "This Mac is already enrolled with this key (agent $current_id); keeping its identity and configuration."
    fi

    ensure_service_account

    # Stop a previous install: it must not rewrite the config while we replace it.
    stop_job "$LABEL" "$plist"

    print_status "Installing device agent binary to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR/etc" "$INSTALL_DIR/data" "$LOG_DIR"
    cp "$binary" "$INSTALL_DIR/$EXECUTABLE"
    xattr -d com.apple.quarantine "$INSTALL_DIR/$EXECUTABLE" 2>/dev/null || true
    chmod 755 "$INSTALL_DIR/$EXECUTABLE"

    # The installer does NOT register the agent. The agent enrolls itself on
    # first start: it generates its keypair locally (the private key never
    # leaves the Mac), sends a CSR, and rewrites this file with the agent ID
    # the platform accepted, the mTLS endpoint it was given and its data path,
    # where the client certificate and the platform CA are kept. The config
    # and the data path belong to the service account; the binary does not.
    if [[ "$keep_enrollment" != "true" ]]; then
        print_status "Creating configuration file..."
        # A fresh enrollment must not inherit a previous agent's certificate.
        rm -rf "$INSTALL_DIR/data/certs"
        # Holds the registration key until the agent redeems it: owner-only
        # before any content is written.
        : > "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
        cat > "$CONFIG_FILE" << EOF
# Vista Platform Device Agent configuration (generated by install-device-agent-macos.sh)
platform_url: $(yaml_quote "$CONTROL_PLANE_URL")
registration_key: $(yaml_quote "$REGISTRATION_KEY")
poll_interval: 30s
data_path: $(yaml_quote "$INSTALL_DIR/data")
EOF
    fi

    print_status "Creating launchd job $LABEL..."
    write_service_wrapper "$wrapper"
    local program=("$wrapper" "$log_file" "$INSTALL_DIR/$EXECUTABLE" -config "$CONFIG_FILE" -interactive=false)
    if [[ -n "$CA_FINGERPRINT" ]]; then
        # Pins the platform's CA on first start, verified against this
        # fingerprint; ignored once a CA is in the config. macOS does not let
        # a script change certificate trust without a person at the screen,
        # so this is the unattended way to trust a private CA.
        program+=(-ca-fingerprint "$CA_FINGERPRINT")
    fi
    PLIST_ENV=()
    write_launchd_plist "$plist" "$LABEL" "$SERVICE_USER" "$INSTALL_DIR" "$LOG_DIR/launchd.log" "${program[@]}"
    if ! plutil -lint "$plist" >/dev/null; then
        print_error "The launchd job description $plist is not valid"
        exit 1
    fi

    # The program files are root's, so the account cannot replace what it
    # runs; what the agent writes (its config, certificates, logs) is the
    # account's.
    chown -R root:wheel "$INSTALL_DIR" "$plist"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/etc" "$INSTALL_DIR/data" "$LOG_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$INSTALL_DIR/etc" "$INSTALL_DIR/data"
    chmod 750 "$LOG_DIR"
    chmod 600 "$CONFIG_FILE"
    chmod 644 "$plist"

    print_status "Starting the device agent; it enrolls itself with the platform..."
    local log_offset start_epoch
    log_offset=$(size_of "$log_file")
    start_epoch=$(date +%s)
    if ! start_job "$LABEL" "$plist"; then
        print_error "launchd did not start the device agent job"
        print_status "Check: sudo launchctl print system/$LABEL"
        exit 1
    fi

    # Enrollment is confirmed only by the agent itself: it rewrites agent_id
    # with the ID the platform accepted. A running job is not an enrolled agent.
    print_status "Waiting up to ${REGISTRATION_TIMEOUT}s for the agent to enroll..."
    local agent_id="" rejected=false
    while (( $(date +%s) - start_epoch < REGISTRATION_TIMEOUT )); do
        current_id=$(read_config_value agent_id "$CONFIG_FILE")
        if [[ "$current_id" =~ $uuid_re ]]; then
            agent_id="$current_id"
            break
        fi
        if log_since "$log_file" "$log_offset" \
            | grep -q -E 'Registration was REJECTED|cannot store its enrollment|exited with status 78'; then
            rejected=true
            break
        fi
        sleep 2
    done

    if [[ -z "$agent_id" ]]; then
        echo ""
        show_log_tail "$log_file" "$log_offset"
        echo ""
        if [[ "$rejected" == "true" ]]; then
            # A rejected key never succeeds; leave the job stopped and off at
            # boot until the installer runs again.
            stop_job "$LABEL" "$plist"
            launchctl disable "system/$LABEL" 2>/dev/null || true
            print_error "The agent could not enroll (see above). If the key was rejected it is invalid, expired, or already used."
            print_error "Generate a new key (Discovery → Sensors & Agents → Register → Device agent) and re-run this installer with it."
            print_status "The device agent job has been stopped and disabled."
        else
            print_error "The agent did not enroll within ${REGISTRATION_TIMEOUT}s."
            print_status "It is still running and retrying; check that $CONTROL_PLANE_URL is reachable from this Mac."
            print_status "Watch it with: sudo tail -f $log_file"
        fi
        exit 1
    fi

    if ! job_running "$LABEL"; then
        print_error "❌ The agent enrolled but is not running"
        show_log_tail "$log_file" "$log_offset"
        print_status "Check: sudo launchctl print system/$LABEL"
        exit 1
    fi

    print_header "🎉 Installation Complete!"
    echo "================================"
    echo "Agent ID: $agent_id"
    echo "Agent Version: ${version:-unknown}"
    echo "Installation Directory: $INSTALL_DIR"
    echo "Configuration: $CONFIG_FILE"
    echo "launchd job: $LABEL ($plist), running as $SERVICE_USER"
    echo "Log: $log_file"
    echo ""
    echo "📋 Management Commands:"
    echo "  Status:     sudo launchctl print system/$LABEL"
    echo "  Logs:       sudo tail -f $log_file"
    echo "  Restart:    sudo launchctl kickstart -k system/$LABEL"
    echo "  Stop:       sudo launchctl bootout system/$LABEL"
    echo "  Uninstall:  sudo bash $0 --uninstall"
    echo ""
    print_status "The agent is enrolled and polling for interrogation jobs."
    print_status "It appears under Discovery → Sensors & Agents once its first heartbeat arrives."
}

# Sourcing the file (the tests do) defines the functions without installing.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
