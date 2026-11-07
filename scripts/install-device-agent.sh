#!/bin/bash

# Vista Platform Device Agent installer (Linux, systemd).
#
# Installs the device agent (./device-agent, or the loose release file
# vista-device-agent_<version>_linux_<arch>) as a service, writes its configuration, starts it,
# and waits for the agent to enroll itself with the platform. The counterpart
# of install-sensor.sh: the same steps, the same output, the same
# re-run-to-upgrade behaviour.
#
# Usage: sudo bash install-device-agent.sh --url URL --key KEY [options]

set -e

CONTROL_PLANE_URL=""
# The key may come from the environment so it stays out of the process list.
REGISTRATION_KEY="${VISTA_REGISTRATION_KEY:-}"
CA_FINGERPRINT=""
INSTALL_DIR="/opt/vista-device-agent"
DIR_GIVEN=false
SERVICE_NAME="vista-device-agent"
SERVICE_USER="vista-device-agent"
UNIT_DIR="/etc/systemd/system"
CONFIG_NAME="device-agent.yaml"
INSTALLED_BINARY="vista-device-agent"
# What earlier releases called them. See migrate_legacy_install.
LEGACY_NAME="crypto-device-agent"
LEGACY_DEFAULT_DIR="/opt/crypto-device-agent"
LEGACY_BINARY="device-agent"
MIGRATION_STEP=""
UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
CHECK_DEPENDENCIES=false
REGISTRATION_TIMEOUT=${REGISTRATION_TIMEOUT:-90}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
print_header()  { echo -e "${BLUE}$1${NC}"; }

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

show_usage() {
    cat << EOF
Vista Platform Device Agent Installer
=====================================

Usage: $0 --url URL --key KEY [options]

Options:
    -u, --url URL              Platform URL, as shown in the console (required unless
                               this host is already enrolled)
    -k, --key KEY              Registration key (required unless this host is already
                               enrolled). A key on the command line is
                               visible to other users in the process list; prefer one of:
    --key-stdin                Read the key from the first line of standard input
                               (VISTA_REGISTRATION_KEY=... in the environment also works)
    --ca-fingerprint SHA256    Expected SHA-256 fingerprint of the platform's CA, for a
                               platform whose certificate this host does not already trust
    -d, --dir DIRECTORY        Installation directory (default: $INSTALL_DIR)
    --check-dependencies       Check the agent binary runs on this host, then exit (no root needed)
    -h, --help                 Show this help

Run it from the directory holding the downloaded agent: the contents of the
.tar.gz archive (./device-agent), or the loose vista-device-agent_<version>_linux_<arch>.
Re-running it keeps the agent's enrollment and replaces only the binary, which
is how to upgrade it; a host installed under the old crypto-device-agent names
moves to the vista-device-agent names on the way, with no new key.
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--url) CONTROL_PLANE_URL="$2"; shift 2 ;;
        -k|--key) REGISTRATION_KEY="$2"; shift 2 ;;
        --key-stdin) read_key_from_stdin; shift ;;
        --ca-fingerprint) CA_FINGERPRINT="$2"; shift 2 ;;
        -d|--dir) INSTALL_DIR="$2"; DIR_GIVEN=true; shift 2 ;;
        --check-dependencies) CHECK_DEPENDENCIES=true; shift ;;
        -h|--help) show_usage; exit 0 ;;
        *) print_error "Unknown option: $1"; show_usage; exit 1 ;;
    esac
done

# Prints the value of a top-level `key: value` line in the agent config, with
# optional surrounding double quotes removed (the agent writes agent_id and
# data_path quoted; the installer quotes every value it writes).
read_config_value() {
    sed -n "s/^$1:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*\$/\1/p" "$2" 2>/dev/null | head -1
}

# Prints the SHA-256 (hex) of its argument.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | cut -d' ' -f1
    else
        printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
    fi
}

# True when the config at $1 records that this host enrolled with registration
# key $2: either the key itself (a config written before the agent stopped
# keeping it) or its SHA-256 fingerprint, which is all it keeps once the
# platform has issued the per-agent secret that replaced it.
enrolled_with_key() {
    [[ "$(read_config_value registration_key "$1")" == "$2" ]] && return 0
    [[ "$(read_config_value registration_key_sha256 "$1")" == "$(sha256_of "$2")" ]]
}

# Creates the service user if it does not exist.
create_service_user() {
    print_status "Creating service user: $SERVICE_USER"
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
    fi
}

# --- shared Linux migration functions (begin) ---
# This block is byte-identical in install-sensor.sh and install-device-agent.sh;
# scripts/install-linux-migration.test.mjs holds them equal.
#
# Earlier releases installed under the crypto-* names. Re-running the installer
# moves such a host to the Vista names and keeps its enrollment. Each step checks
# what is on disk rather than assuming the one before it ran, so a run that
# stopped part-way is finished by running the installer again.

# Prints the value of a `Name=value` line in a systemd unit.
unit_value() {
    sed -n "s/^$1=//p" "$2" 2>/dev/null | head -1
}

# Works out where this host's install is. Sets LEGACY_DIR, LEGACY_UNIT, NEW_UNIT,
# CONFIG_FILE and EXISTING_CONFIG, and INSTALL_DIR unless --dir chose it. Changes
# nothing. A directory an operator chose stays where it is.
locate_install() {
    local current
    INSTALL_DIR=${INSTALL_DIR%/}
    LEGACY_UNIT="$UNIT_DIR/$LEGACY_NAME.service"
    NEW_UNIT="$UNIT_DIR/$SERVICE_NAME.service"
    LEGACY_DIR=$(unit_value WorkingDirectory "$LEGACY_UNIT")
    LEGACY_DIR=${LEGACY_DIR:-$LEGACY_DEFAULT_DIR}
    if [[ "$DIR_GIVEN" != "true" ]]; then
        current=$(unit_value WorkingDirectory "$NEW_UNIT")
        if [[ -n "$current" ]]; then
            INSTALL_DIR=$current
        elif [[ "$LEGACY_DIR" != "$LEGACY_DEFAULT_DIR" ]]; then
            INSTALL_DIR=$LEGACY_DIR
        fi
    fi
    CONFIG_FILE="$INSTALL_DIR/$CONFIG_NAME"
    EXISTING_CONFIG=$CONFIG_FILE
    if [[ ! -f "$CONFIG_FILE" && -f "$LEGACY_DIR/$CONFIG_NAME" ]]; then
        EXISTING_CONFIG="$LEGACY_DIR/$CONFIG_NAME"
    fi
}

# Replaces directory $2 with $3 in the config at $1, as a whole path component:
# /opt/name-backup is another directory. Fails rather than start a service on a
# config that still names a directory that has gone.
rewrite_config_paths() {
    local config=$1 old=$2 new=$3 escaped replacement pattern before after
    if [[ "$old" == "$new" || ! -f "$config" ]]; then
        return 0
    fi
    escaped=$(printf '%s' "$old" | sed 's/[][\.*^$+?(){}|#]/\\&/g')
    replacement=$(printf '%s' "$new" | sed 's/[&#\]/\\&/g')
    pattern="(^|[^[:alnum:]_./-])$escaped(/|[^[:alnum:]_./-]|\$)"
    before=$(grep -cE "$pattern" "$config" || true)
    if [[ "$before" -eq 0 ]]; then
        return 0
    fi
    sed -i -E "s#$pattern#\\1$replacement\\2#g" "$config"
    after=$(grep -cE "$pattern" "$config" || true)
    if [[ "$after" -ne 0 ]] || ! grep -qF "$new" "$config"; then
        print_error "Could not rewrite $old to $new in $config ($after of $before lines still name it)."
        print_error "Edit those lines by hand so they name $new, then run this installer again."
        return 1
    fi
    print_status "Updated $before line(s) of $config to name $new."
}

# Moves LEGACY_DIR to INSTALL_DIR. A rename cannot be left half done; across
# filesystems the copy appears under its final name only once it is complete, and
# the original goes only after that.
move_legacy_dir() {
    local parent staging="$INSTALL_DIR.migrating"
    parent=$(dirname "$INSTALL_DIR")
    mkdir -p "$parent"
    if [[ -d "$INSTALL_DIR" ]]; then
        rmdir "$INSTALL_DIR"
    fi
    if [[ "$(stat -c %d "$LEGACY_DIR")" == "$(stat -c %d "$parent")" ]]; then
        mv -T "$LEGACY_DIR" "$INSTALL_DIR"
    else
        rm -rf "$staging"
        cp -a "$LEGACY_DIR" "$staging"
        mv -T "$staging" "$INSTALL_DIR"
        rm -rf "$LEGACY_DIR"
    fi
    print_status "Moved $LEGACY_DIR to $INSTALL_DIR"
}

# Removes the old service user once nothing runs as it. Never `userdel -r`: its
# home directory is the install directory.
remove_legacy_user() {
    local found=0
    if ! id "$LEGACY_NAME" &>/dev/null; then
        return 0
    fi
    pgrep -u "$LEGACY_NAME" >/dev/null 2>&1 || found=$?
    if [[ "$found" -ne 1 ]]; then
        print_warning "Left user $LEGACY_NAME in place: a process may still run as it. Run this installer again once none does, or: userdel $LEGACY_NAME"
        return 0
    fi
    if ! userdel "$LEGACY_NAME"; then
        print_warning "Could not remove user $LEGACY_NAME; nothing depends on it. Remove it with: userdel $LEGACY_NAME"
        return 0
    fi
    if getent group "$LEGACY_NAME" >/dev/null 2>&1; then
        groupdel "$LEGACY_NAME" 2>/dev/null || true
    fi
    print_status "Removed user $LEGACY_NAME"
}

# Says what to do when the run ends with an install taken apart.
migration_exit() {
    local status=$?
    if [[ "$status" -eq 0 || -z "$MIGRATION_STEP" ]]; then
        return 0
    fi
    print_error "The move from $LEGACY_NAME to $SERVICE_NAME stopped while $MIGRATION_STEP; the service is not running."
    print_error "Its configuration, certificates and data are in $( [[ -f "$CONFIG_FILE" ]] && echo "$INSTALL_DIR" || echo "$LEGACY_DIR" )."
    print_status "Fix the cause above, then run this installer again with the same options: it carries on from here, and a host that is already enrolled needs no key."
}

# Takes a legacy install apart and leaves INSTALL_DIR holding what it held, for
# the normal install path to finish. Does nothing on a host without one.
migrate_legacy_install() {
    local move=false keep_dir=false
    if [[ ! -f "$LEGACY_UNIT" && ! -d "$LEGACY_DIR" ]]; then
        # An earlier run may have stopped just after the move.
        rewrite_config_paths "$CONFIG_FILE" "$LEGACY_DIR" "$INSTALL_DIR"
        remove_legacy_user
        return 0
    fi
    if [[ -d "$LEGACY_DIR" && "$LEGACY_DIR" != "$INSTALL_DIR" ]]; then
        if [[ -f "$CONFIG_FILE" ]]; then
            keep_dir=true
        elif [[ -e "$INSTALL_DIR" && ( ! -d "$INSTALL_DIR" || -n "$(ls -A "$INSTALL_DIR")" ) ]]; then
            print_error "$INSTALL_DIR already exists and is not empty, so $LEGACY_DIR cannot move there. Nothing was changed."
            print_error "Empty it, or choose another directory with --dir."
            exit 1
        else
            move=true
        fi
    fi

    print_status "Moving this host from $LEGACY_NAME to $SERVICE_NAME; its enrollment is kept."
    trap migration_exit EXIT
    if [[ -f "$LEGACY_UNIT" ]]; then
        MIGRATION_STEP="stopping $LEGACY_NAME.service"
        systemctl stop "$LEGACY_NAME.service" 2>/dev/null || true
        if systemctl is-active --quiet "$LEGACY_NAME.service"; then
            MIGRATION_STEP=""
            print_error "$LEGACY_NAME.service did not stop; nothing else was changed. Stop it, then run this installer again."
            exit 1
        fi
        systemctl disable "$LEGACY_NAME.service" 2>/dev/null || true
    fi
    if [[ "$move" == "true" ]]; then
        MIGRATION_STEP="moving $LEGACY_DIR to $INSTALL_DIR"
        move_legacy_dir
    fi
    MIGRATION_STEP="rewriting the paths in $CONFIG_FILE"
    rewrite_config_paths "$CONFIG_FILE" "$LEGACY_DIR" "$INSTALL_DIR"

    MIGRATION_STEP="handing $INSTALL_DIR to user $SERVICE_USER"
    create_service_user
    if [[ -d "$INSTALL_DIR" ]]; then
        chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    fi

    MIGRATION_STEP="removing $LEGACY_NAME.service"
    if [[ -d "$LEGACY_UNIT.d" ]]; then
        rm -rf "$NEW_UNIT.d"
        mv -T "$LEGACY_UNIT.d" "$NEW_UNIT.d"
        print_warning "Kept the local overrides in $NEW_UNIT.d; check them for the old names."
    fi
    rm -f "$LEGACY_UNIT"
    systemctl daemon-reload
    if [[ "$keep_dir" == "true" ]]; then
        print_warning "$CONFIG_FILE already exists, so $LEGACY_DIR was not moved and its contents were not used. Remove it, and user $LEGACY_NAME, once you no longer need them."
    else
        remove_legacy_user
    fi
    MIGRATION_STEP="installing $SERVICE_NAME.service"
}
# --- shared Linux migration functions (end) ---

# Finds the binary to install and sets BINARY: ./$1 (its name in the release
# archive), else the one loose release file for this host,
# ./$2_<version>_linux_<arch>. Fails, naming both, otherwise.
resolve_binary() {
    local installed=$1 prefix=$2 arch f count=0
    BINARY=""
    if [[ -f "./$installed" ]]; then
        BINARY="./$installed"
        return 0
    fi
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) arch=$(uname -m) ;;
    esac
    for f in ./"${prefix}"_*_linux_"${arch}"; do
        [[ -f "$f" ]] || continue
        BINARY=$f
        count=$((count + 1))
    done
    if [[ $count -eq 1 ]]; then
        return 0
    fi
    if [[ $count -gt 1 ]]; then
        BINARY=""
        print_error "Several ${prefix}_<version>_linux_${arch} files are in the current directory; keep only the one to install."
        return 1
    fi
    print_error "$3 binary not found in the current directory."
    print_error "Download and verify the Linux build for this host's architecture ($arch), and place it here either as ./$installed (its name in the .tar.gz archive) or under its release name ${prefix}_<version>_linux_${arch}."
    return 1
}

# The agent is statically linked; running it proves it is the right build for
# this host's architecture. --version exits before configuration or enrollment.
check_agent_binary() {
    local binary output
    resolve_binary device-agent vista-device-agent "Device agent" || return 1
    binary=$BINARY
    if [[ ! -x "$binary" ]]; then
        print_error "Device agent binary is not executable. Run: chmod +x $binary"
        return 1
    fi
    if output=$(LC_ALL=C "$binary" -version 2>&1); then
        print_status "Device agent runs on this host."
        return 0
    fi
    print_error "The device agent cannot run on this host. Installation stopped before anything was changed."
    printf '%s\n' "$output"
    print_error "Check that the binary matches this host's architecture (amd64 or arm64)."
    return 1
}

if [[ $(uname -s) != Linux ]]; then
    print_error "This installer requires Linux with systemd. On macOS use install-device-agent-macos.sh; on Windows use install-device-agent.ps1."
    exit 1
fi

if [[ "$CHECK_DEPENDENCIES" == "true" ]]; then
    check_agent_binary
    exit $?
fi

check_agent_binary

locate_install

# An existing install may be enrolled already; that is checked as root below.
if [[ ( -z "$CONTROL_PLANE_URL" || -z "$REGISTRATION_KEY" ) && ! -f "$EXISTING_CONFIG" ]]; then
    print_error "--url and --key are required"
    show_usage
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Nothing has changed yet. Without a key, only an enrolled host can go on, and it
# keeps the platform it enrolled with.
if [[ -z "$REGISTRATION_KEY" ]] \
    && ! [[ "$(read_config_value agent_id "$EXISTING_CONFIG")" =~ $UUID_RE ]]; then
    print_error "--url and --key are required: $EXISTING_CONFIG does not record an enrolled agent."
    exit 1
fi
if [[ -z "$CONTROL_PLANE_URL" ]]; then
    CONTROL_PLANE_URL=$(read_config_value platform_url "$EXISTING_CONFIG")
fi
if [[ -z "$CONTROL_PLANE_URL" ]]; then
    print_error "--url is required: $EXISTING_CONFIG does not record a platform."
    exit 1
fi

AGENT_VERSION=$("$BINARY" -version 2>/dev/null | head -1 | sed -n 's/.* v\([^ ]*\)$/\1/p')

print_header "🚀 Vista Platform Device Agent Installer"
echo "=================================================="
echo "  Agent Version: ${AGENT_VERSION:-unknown}"
echo "  Platform: $CONTROL_PLANE_URL"
echo "  Install Directory: $INSTALL_DIR"

# Step 1: Move an install made under the old names, then the service user
migrate_legacy_install
create_service_user

# Step 2: Directories
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/data"

# A host this key already enrolled keeps its identity, and so does one re-run
# with no key at all. Re-running the install (to upgrade the binary, or by
# mistake) must not discard the certificate and agent ID and send it back to
# register with a key it has already spent. A different key means a fresh
# enrollment.
KEEP_ENROLLMENT=false
if [[ -f "$CONFIG_FILE" ]] \
    && [[ "$(read_config_value agent_id "$CONFIG_FILE")" =~ $UUID_RE ]] \
    && { [[ -z "$REGISTRATION_KEY" ]] || enrolled_with_key "$CONFIG_FILE" "$REGISTRATION_KEY"; }; then
    KEEP_ENROLLMENT=true
    print_status "This host is already enrolled (agent $(read_config_value agent_id "$CONFIG_FILE")); keeping its identity and configuration."
fi

# Stop a previous install: its binary cannot be replaced while it runs ("Text
# file busy"), and it must not rewrite the config while we replace it.
systemctl stop "$SERVICE_NAME.service" 2>/dev/null || true

# Step 3: Binary
print_status "Installing device agent binary..."
cp "$BINARY" "$INSTALL_DIR/$INSTALLED_BINARY"
chmod 755 "$INSTALL_DIR/$INSTALLED_BINARY"

# Step 4: Configuration
#
# The installer does NOT register the agent. The agent enrolls itself on first
# start: it generates its keypair locally (the private key never leaves the
# host), sends a CSR, and rewrites this file with the agent ID the platform
# accepted, the mTLS endpoint it was given and its data path — where the client
# certificate and the platform CA that signs that endpoint are kept. The data
# path is inside the install directory and owned by the service user; the
# agent's own default under /var/lib is root-owned, which is how running it by
# hand as an ordinary user spent the key on an enrollment it could not save.
if [[ "$KEEP_ENROLLMENT" != "true" ]]; then
    print_status "Creating configuration file..."
    # A fresh enrollment must not inherit a previous agent's certificate.
    rm -rf "$INSTALL_DIR/data/certs"
    # Holds the registration key until the agent redeems it: owner-only before
    # any content is written (cat > keeps the mode of the file it truncates).
    : > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    cat > "$CONFIG_FILE" << EOF
# Vista Platform Device Agent configuration (generated by install-device-agent.sh)
platform_url: $(yaml_quote "$CONTROL_PLANE_URL")
registration_key: $(yaml_quote "$REGISTRATION_KEY")
poll_interval: 30s
data_path: $(yaml_quote "$INSTALL_DIR/data")
EOF
fi

# Step 5: systemd service
print_status "Creating systemd service..."
EXEC_START="$INSTALL_DIR/$INSTALLED_BINARY -config $CONFIG_FILE -interactive=false"
if [[ -n "$CA_FINGERPRINT" ]]; then
    # Pins the platform's CA on first start, verified against this
    # fingerprint; ignored once a CA is in the config.
    EXEC_START+=" -ca-fingerprint $CA_FINGERPRINT"
fi
cat > "$NEW_UNIT" << EOF
[Unit]
Description=Vista Platform Device Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
# Enrolls on first start with the key in the config, then runs from the
# certificate it was issued. A failed enrollment exits; the restart retries,
# except for exit status 78 (EX_CONFIG): a rejected registration key or an
# unusable config needs a person, and restarting would only repeat it.
ExecStart=$EXEC_START
Restart=always
RestartSec=10
RestartPreventExitStatus=78
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

# Step 6: Permissions. The agent rewrites its config and writes its
# certificate under data/, so the service user must own both.
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chmod 600 "$CONFIG_FILE"

# Step 7: Start; the agent enrolls itself
print_status "Starting the device agent; it enrolls itself with the platform..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME.service"
START_EPOCH=$(date +%s)
if ! systemctl restart "$SERVICE_NAME.service"; then
    print_error "Failed to start the device agent service"
    print_status "Check logs with: journalctl -u $SERVICE_NAME -f"
    exit 1
fi
MIGRATION_STEP=""
# The old binary came along with the directory.
if [[ ! "$INSTALL_DIR/$LEGACY_BINARY" -ef "$BINARY" ]]; then
    rm -f "$INSTALL_DIR/$LEGACY_BINARY"
fi

# Step 8: Wait for enrollment
#
# Enrollment is confirmed only by the agent itself: it rewrites agent_id with
# the ID the platform accepted. A running service is not an enrolled agent.
print_status "Waiting up to ${REGISTRATION_TIMEOUT}s for the agent to enroll..."
AGENT_ID=""
REJECTED=false
while (( $(date +%s) - START_EPOCH < REGISTRATION_TIMEOUT )); do
    current_id=$(read_config_value agent_id "$CONFIG_FILE")
    if [[ "$current_id" =~ $UUID_RE ]]; then
        AGENT_ID="$current_id"
        break
    fi
    if journalctl -u "$SERVICE_NAME.service" --since "@$START_EPOCH" --no-pager -o cat 2>/dev/null \
        | grep -q -E 'Registration was REJECTED|cannot store its enrollment'; then
        REJECTED=true
        break
    fi
    sleep 2
done

if [[ -z "$AGENT_ID" ]]; then
    echo ""
    journalctl -u "$SERVICE_NAME.service" --since "@$START_EPOCH" --no-pager -o cat 2>/dev/null \
        | grep -E '⛔|❌' | tail -8 || true
    echo ""
    if [[ "$REJECTED" == "true" ]]; then
        # A rejected key never succeeds; stop the service rather than leave it
        # restarting every 10 seconds.
        systemctl stop "$SERVICE_NAME.service" || true
        systemctl disable "$SERVICE_NAME.service" 2>/dev/null || true
        print_error "The agent could not enroll (see above). If the key was rejected it is invalid, expired, or already used."
        print_error "Generate a new key (Discovery → Sensors & Agents → Register → Device agent) and re-run this installer with it."
        print_status "The device agent service has been stopped and disabled."
    else
        print_error "The agent did not enroll within ${REGISTRATION_TIMEOUT}s."
        print_status "It is still running and retrying; check that $CONTROL_PLANE_URL is reachable from this host."
        print_status "Watch it with: journalctl -u $SERVICE_NAME -f"
    fi
    exit 1
fi

if ! systemctl is-active --quiet "$SERVICE_NAME.service"; then
    print_error "❌ The agent enrolled but is not running"
    print_status "Check logs with: journalctl -u $SERVICE_NAME -f"
    exit 1
fi

print_header "🎉 Installation Complete!"
echo "================================"
echo "Agent ID: $AGENT_ID"
echo "Agent Version: ${AGENT_VERSION:-unknown}"
echo "Installation Directory: $INSTALL_DIR"
echo "Configuration: $CONFIG_FILE"
echo "Service: $SERVICE_NAME.service"
echo ""
echo "📋 Management Commands:"
echo "  Status:     systemctl status $SERVICE_NAME"
echo "  Logs:       journalctl -u $SERVICE_NAME -f"
echo "  Restart:    systemctl restart $SERVICE_NAME"
echo "  Uninstall:  systemctl stop $SERVICE_NAME && systemctl disable $SERVICE_NAME"
echo ""
print_status "The agent is enrolled and polling for interrogation jobs."
print_status "It appears under Discovery → Sensors & Agents once its first heartbeat arrives."
