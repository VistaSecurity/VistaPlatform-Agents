#!/bin/bash

# Vista Platform Sensor installer (Linux, systemd).
# Usage: sudo bash install-sensor.sh --key KEY --ip ADDRESS [options]

set -e

UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# Default values
CONTROL_PLANE_URL="https://app.vistasecurity.io"
# The key may come from the environment so it stays out of the process list.
REGISTRATION_KEY="${VISTA_REGISTRATION_KEY:-}"
SENSOR_NAME=""
INTERFACES=""
PROFILE="datacenter_host"
INSTALL_DIR="/opt/vista-sensor"
DIR_GIVEN=false
SERVICE_NAME="vista-sensor"
SERVICE_USER="vista-sensor"
UNIT_DIR="/etc/systemd/system"
CONFIG_NAME="sensor-config.yaml"
INSTALLED_BINARY="vista-sensor"
# What earlier releases called them. See migrate_legacy_install.
LEGACY_NAME="crypto-sensor"
LEGACY_DEFAULT_DIR="/opt/crypto-sensor"
LEGACY_BINARY="crypto-sensor"
MIGRATION_STEP=""
VERBOSE=false
EXPECTED_IP=""
CA_FINGERPRINT=""
INTERACTIVE=false
CHECK_DEPENDENCIES=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

# Show usage
show_usage() {
    cat << EOF
Vista Platform Sensor Installer
===============================

Usage: $0 [options]

Options:
    -u, --url URL              Control plane URL (default: $CONTROL_PLANE_URL)
    -k, --key KEY              Registration key (required unless this host is already
                               enrolled). A key on the command line is
                               visible to other users in the process list; prefer one of:
    --key-stdin                Read the key from the first line of standard input
                               (VISTA_REGISTRATION_KEY=... in the environment also works)
    -n, --name NAME            Sensor name (default: auto-detect)
    -i, --interfaces IFACES    Network interfaces (default: auto-detect)
    -p, --profile PROFILE      Deployment profile (default: $PROFILE; not yet applied —
                               the sensor registers as datacenter_host)
    -d, --dir DIRECTORY        Installation directory (default: $INSTALL_DIR)
    --ip IP_ADDRESS            Expected IP address for validation (required on a first
                               install; a re-run reuses the address in the service)
    --ca-fingerprint SHA256    Expected SHA-256 fingerprint of the platform's CA, for a
                               platform whose certificate this host does not already trust
    --interactive              Run in interactive mode (ask for all settings)
    --check-dependencies       Check the sensor binary can load, then exit (no root needed)
    --verbose                  Enable verbose output
    -h, --help                 Show this help

Run it from the directory holding the downloaded sensor: the contents of the
.tar.gz archive (./crypto-sensor), or the loose vista-sensor_<version>_linux_<arch>.
Re-running it keeps an enrolled sensor's identity and replaces the binary, which
is how to upgrade it; a host installed under the old crypto-sensor names moves to
the vista-sensor names on the way, with no new key.

Examples:
    # Interactive installation (recommended)
    $0 --interactive

    # Basic installation with arguments
    $0 --key REG-550e8400-20241215-A7B3C9 --ip 192.0.2.10

    # Custom configuration
    $0 --key REG-550e8400-20241215-A7B3C9 \\
       --ip 192.0.2.10 \\
       --name sensor-dc01 \\
       --interfaces "eth0,eth1" \\
       --profile datacenter_host

    # Air-gapped installation
    $0 --key REG-550e8400-20241215-A7B3C9 \\
       --ip 10.0.1.50 \\
       --profile air_gapped \\
       --interfaces "eth0"

Profiles:
    - end_user_machine    : Minimal footprint, single interface
    - datacenter_host     : Full features, multiple interfaces
    - cloud_instance      : Cloud-optimized, periodic reporting
    - air_gapped         : Offline mode, export files

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--url)
            CONTROL_PLANE_URL="$2"
            shift 2
            ;;
        -k|--key)
            REGISTRATION_KEY="$2"
            shift 2
            ;;
        --key-stdin)
            read_key_from_stdin
            shift
            ;;
        -n|--name)
            SENSOR_NAME="$2"
            shift 2
            ;;
        -i|--interfaces)
            INTERFACES="$2"
            shift 2
            ;;
        -p|--profile)
            PROFILE="$2"
            shift 2
            ;;
        -d|--dir)
            INSTALL_DIR="$2"
            DIR_GIVEN=true
            shift 2
            ;;
        --ip)
            EXPECTED_IP="$2"
            shift 2
            ;;
        --ca-fingerprint)
            CA_FINGERPRINT="$2"
            shift 2
            ;;
        --interactive)
            INTERACTIVE=true
            shift
            ;;
        --check-dependencies)
            CHECK_DEPENDENCIES=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Prints the value of a top-level `key: value` line in the sensor config, with
# optional surrounding double quotes removed (the sensor writes sensorId quoted
# and controlPlaneUrl bare).
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
# key $2: either the key itself (a config written before the sensor stopped
# keeping it) or its SHA-256 fingerprint, which is all it keeps once the
# platform has issued the per-sensor secret that replaced it.
enrolled_with_key() {
    [[ "$(read_config_value registrationKey "$1")" == "$2" ]] && return 0
    [[ "$(read_config_value registrationKeySha256 "$1")" == "$(sha256_of "$2")" ]]
}

# Creates the service user if it does not exist.
create_service_user() {
    print_status "Creating service user: $SERVICE_USER"
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
        print_status "Service user created"
    else
        print_status "Service user already exists"
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

# Run the actual binary: a library filename or installed package alone does not
# prove that its architecture, SONAME and transitive dependencies are compatible.
# --version exits before configuration, registration or packet capture.
check_sensor_dependencies() {
    local binary loader_output
    resolve_binary crypto-sensor vista-sensor Sensor || return 1
    binary=$BINARY
    if [[ ! -x "$binary" ]]; then
        print_error "Sensor binary is not executable. Run: chmod +x $binary"
        return 1
    fi
    if loader_output=$(LC_ALL=C "$binary" --version 2>&1); then
        print_status "Sensor runtime dependencies are available."
        return 0
    fi

    print_error "The sensor cannot load. Installation stopped before creating users, writing configuration or registering with the control plane."
    print_error "The Linux sensor requires the libpcap runtime and a compatible system loader."
    printf '%s\n' "$loader_output"
    print_status "If libpcap is missing, install it using your distribution's package manager:"
    echo "  Debian / Ubuntu:                    sudo apt-get update && sudo apt-get install libpcap0.8"
    echo "                                      (apt installs libpcap0.8t64 on Ubuntu 24.04+ / Debian 13+)"
    echo "  RHEL / Fedora / Rocky / Alma:       sudo dnf install libpcap"
    echo "  Amazon Linux 2 / CentOS 7 (yum):    sudo yum install libpcap"
    echo "  SUSE / openSUSE:                    sudo zypper install libpcap1"
    echo "  Arch / Manjaro:                     sudo pacman -S libpcap"
    echo "  For offline hosts, provide the distribution's libpcap package and its dependencies from an approved local repository."
    print_error "If libpcap is installed, check that the binary matches this host's architecture and libc; installing libpcap alone cannot fix an incompatible build."
    echo "  Retry: bash scripts/install-sensor.sh --check-dependencies"
    return 1
}

# This installer installs a systemd service and uses Linux networking tools.
if [[ $(uname -s) != Linux ]]; then
    print_error "This installer requires Linux with systemd. On macOS use install-sensor-macos.sh; on Windows use install-sensor.ps1."
    exit 1
fi

if [[ "$CHECK_DEPENDENCIES" == "true" ]]; then
    check_sensor_dependencies
    exit $?
fi

# Interactive mode function
# Provides a guided, user-friendly installation experience
# Prompts for all required configuration parameters with validation
# Shows available options and provides helpful descriptions
run_interactive_mode() {
    print_header "🎛️ Interactive Sensor Installation"
    echo "======================================"
    echo ""
    print_status "This will guide you through the sensor installation process."
    echo ""

    # Get registration key - required for sensor authentication
    # Format: REG-{tenant_id}-{timestamp}-{checksum}
    # An existing install may already be enrolled and need none.
    if [[ -z "$REGISTRATION_KEY" && -f "$EXISTING_CONFIG" ]]; then
        read -r -s -p "Enter registration key (leave empty to keep this host's enrolment): " REGISTRATION_KEY
        echo ""
    fi
    while [[ -z "$REGISTRATION_KEY" && ! -f "$EXISTING_CONFIG" ]]; do
        read -r -s -p "Enter registration key: " REGISTRATION_KEY
        echo ""
        if [[ -z "$REGISTRATION_KEY" ]]; then
            print_error "Registration key is required"
        fi
    done

    # Get IP address - required for security validation
    # Must match one of the host's network interface IPs
    while [[ -z "$EXPECTED_IP" ]]; do
        read -p "Enter expected IP address: " EXPECTED_IP
        if [[ -z "$EXPECTED_IP" ]]; then
            print_error "IP address is required"
        elif ! [[ $EXPECTED_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            print_error "Invalid IP address format"
            EXPECTED_IP=""
        fi
    done

    # Get sensor name
    read -p "Enter sensor name (default: auto-detect): " SENSOR_NAME_INPUT
    if [[ -n "$SENSOR_NAME_INPUT" ]]; then
        SENSOR_NAME="$SENSOR_NAME_INPUT"
    fi

    # Get control plane URL
    read -p "Enter control plane URL (default: $CONTROL_PLANE_URL): " CONTROL_PLANE_URL_INPUT
    if [[ -n "$CONTROL_PLANE_URL_INPUT" ]]; then
        CONTROL_PLANE_URL="$CONTROL_PLANE_URL_INPUT"
    fi

    # Get profile
    echo ""
    print_status "Available profiles:"
    echo "  1) datacenter_host - Full features, multiple interfaces"
    echo "  2) cloud_instance - Cloud-optimized, periodic reporting"
    echo "  3) end_user_machine - Minimal footprint, single interface"
    echo "  4) air_gapped - Offline mode, export files"
    echo ""
    
    while true; do
        read -p "Select profile (1-4, default: 1): " PROFILE_CHOICE
        case $PROFILE_CHOICE in
            1|"")
                PROFILE="datacenter_host"
                break
                ;;
            2)
                PROFILE="cloud_instance"
                break
                ;;
            3)
                PROFILE="end_user_machine"
                break
                ;;
            4)
                PROFILE="air_gapped"
                break
                ;;
            *)
                print_error "Invalid choice. Please select 1-4."
                ;;
        esac
    done

    # Get network interfaces
    echo ""
    print_status "Available network interfaces:"
    ip -o link show | awk -F': ' '{print "  " $2}' | grep -E '^(eth|ens|enp|wl)' | head -10
    echo ""
    read -p "Enter network interfaces (comma-separated, default: auto-detect): " INTERFACES_INPUT
    if [[ -n "$INTERFACES_INPUT" ]]; then
        INTERFACES="$INTERFACES_INPUT"
    fi

    # Get installation directory
    read -p "Enter installation directory (default: $INSTALL_DIR): " INSTALL_DIR_INPUT
    if [[ -n "$INSTALL_DIR_INPUT" ]]; then
        INSTALL_DIR="$INSTALL_DIR_INPUT"
        DIR_GIVEN=true
    fi

    # Show configuration summary
    echo ""
    print_header "📋 Installation Configuration"
    echo "=================================="
    echo "Registration Key: $(mask_key "$REGISTRATION_KEY")"
    echo "IP Address: $EXPECTED_IP"
    echo "Sensor Name: $SENSOR_NAME"
    echo "Control Plane: $CONTROL_PLANE_URL"
    echo "Profile: $PROFILE"
    echo "Interfaces: $INTERFACES"
    echo "Install Directory: $INSTALL_DIR"
    echo ""

    # Confirm installation
    while true; do
        read -p "Proceed with installation? (y/N): " CONFIRM
        case $CONFIRM in
            [Yy]|[Yy][Ee][Ss])
                break
                ;;
            [Nn]|[Nn][Oo]|"")
                print_status "Installation cancelled."
                exit 0
                ;;
            *)
                print_error "Please answer yes or no."
                ;;
        esac
    done

    echo ""
    print_status "Starting installation..."
}

# Run interactive mode if requested
# Fail before prompts, installation side effects or control-plane registration.
check_sensor_dependencies

locate_install
if [[ -z "$EXPECTED_IP" ]]; then
    # A re-run reuses the address the service was installed with.
    EXPECTED_IP=$(unit_value Environment=SENSOR_IP_ADDRESS "$NEW_UNIT")
    EXPECTED_IP=${EXPECTED_IP:-$(unit_value Environment=SENSOR_IP_ADDRESS "$LEGACY_UNIT")}
fi

if [[ "$INTERACTIVE" == "true" ]]; then
    run_interactive_mode
    locate_install
fi

# Validate required parameters (skip if interactive mode already handled)
if [[ "$INTERACTIVE" != "true" ]]; then
    # An existing install may be enrolled already; that is checked as root below.
    if [[ -z "$REGISTRATION_KEY" && ! -f "$EXISTING_CONFIG" ]]; then
        print_error "Registration key is required"
        show_usage
        exit 1
    fi

    if [[ -z "$EXPECTED_IP" ]]; then
        print_error "Expected IP address is required for validation"
        show_usage
        exit 1
    fi
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Nothing has changed yet. Without a key, only an enrolled host can go on.
if [[ -z "$REGISTRATION_KEY" ]] \
    && ! [[ "$(read_config_value sensorId "$EXISTING_CONFIG")" =~ $UUID_RE ]]; then
    print_error "Registration key is required: $EXISTING_CONFIG does not record an enrolled sensor."
    exit 1
fi

# The version the platform will show is the one stamped into this binary — the
# sensor reports it itself at registration and on every heartbeat.
if [[ -n "$CA_FINGERPRINT" && ! "$CA_FINGERPRINT" =~ ^[0-9A-Fa-f:]+$ ]]; then
    print_error "--ca-fingerprint must be the SHA-256 fingerprint in hexadecimal (colons allowed)"
    exit 1
fi

SENSOR_VERSION=$("$BINARY" --version 2>/dev/null | head -1 | sed -n 's/.* v\([^ ]*\)$/\1/p')

print_header "🚀 Vista Platform Sensor Installer"
echo "=================================================="

# Step 1: Detect environment
print_status "Detecting environment..."

# Detect platform
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Detect network interfaces if not specified
if [[ -z "$INTERFACES" ]]; then
    print_status "Auto-detecting network interfaces..."
    INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp|wl)' | head -5 | tr '\n' ',' | sed 's/,$//')
    if [[ -z "$INTERFACES" ]]; then
        INTERFACES="eth0"
    fi
fi

# Generate sensor name if not specified
if [[ -z "$SENSOR_NAME" ]]; then
    HOSTNAME=$(hostname)
    SENSOR_NAME="sensor-${HOSTNAME}-$(date +%Y%m%d)"
fi

print_status "Environment detected:"
echo "  Platform: $PLATFORM/$ARCH"
echo "  Sensor Version: ${SENSOR_VERSION:-unknown}"
echo "  Interfaces: $INTERFACES"
echo "  Sensor Name: $SENSOR_NAME"
echo "  Profile: $PROFILE"
echo "  Control Plane: $CONTROL_PLANE_URL"
echo "  Expected IP: $EXPECTED_IP"

if [[ "$PROFILE" != "datacenter_host" ]]; then
    print_warning "--profile $PROFILE is not applied yet: the sensor registers itself and reports the datacenter_host profile."
fi

# Step 1.5: Validate IP address
print_status "Validating IP address..."
if ! ip addr show | grep -q "$EXPECTED_IP"; then
    print_error "Expected IP address $EXPECTED_IP not found on any interface"
    print_status "Available IP addresses:"
    ip addr show | grep "inet " | awk '{print "  " $2}' | cut -d'/' -f1
    exit 1
fi
print_status "✅ IP address validation passed"

# Step 2: Move an install made under the old names, then create the service user
migrate_legacy_install
create_service_user

# Step 3: Create installation directory
print_status "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/data"
mkdir -p "$INSTALL_DIR/logs"

# A host this key already enrolled keeps its identity, and so does one re-run
# with no key at all. Re-running the install (to upgrade the binary, or by
# mistake) must not discard the certificate and UUID the sensor holds and send
# it back to register with a key it has already spent. A different key means the
# operator wants a fresh enrolment, and gets one.
KEEP_ENROLMENT=false
if [[ -f "$CONFIG_FILE" ]] \
    && [[ "$(read_config_value sensorId "$CONFIG_FILE")" =~ $UUID_RE ]] \
    && { [[ -z "$REGISTRATION_KEY" ]] || enrolled_with_key "$CONFIG_FILE" "$REGISTRATION_KEY"; }; then
    KEEP_ENROLMENT=true
    print_status "This host is already enrolled (sensor $(read_config_value sensorId "$CONFIG_FILE")); keeping its identity and configuration."
    # The sensor keeps talking to the platform in its config; say that one.
    CONFIGURED_URL=$(read_config_value controlPlaneUrl "$CONFIG_FILE")
    CONTROL_PLANE_URL=${CONFIGURED_URL:-$CONTROL_PLANE_URL}
fi

# Stop a previous install: its binary cannot be replaced while it runs ("Text
# file busy"), and it must not rewrite the config while we replace it.
systemctl stop "$SERVICE_NAME.service" 2>/dev/null || true

# Step 4: Install sensor binary
print_status "Installing sensor binary..."
cp "$BINARY" "$INSTALL_DIR/$INSTALLED_BINARY"
chmod +x "$INSTALL_DIR/$INSTALLED_BINARY"
print_status "Sensor binary installed"

# Step 5: Create configuration file
#
# The installer does NOT register the sensor. The sensor binary registers itself
# on first start: it generates its keypair locally (the private key never leaves
# the host), proposes a UUID, sends a CSR along with its build-stamped version
# and capabilities, then rewrites this file with the UUID and the paths of the
# certificate it was issued. An installer that registered on the sensor's behalf
# spent the single-use key before the binary could use it, recorded a version
# the installer made up rather than the binary's, and left the sensor unable to
# enrol — it retried "Registration key has already been used" while the console
# showed a sensor that had never heartbeated.
#
# sensorId carries the sensor NAME until registration: the loader uses a
# non-UUID sensorId as the registration name, and the sensor replaces it with
# the UUID the platform accepts. Flat camelCase keys — the schema the loader
# (sensor/internal/config.ConfigFile) parses; a nested control_plane:/url: block
# is silently ignored.
if [[ "$KEEP_ENROLMENT" != "true" ]]; then
    print_status "Creating configuration file..."

    # Earlier versions of this installer registered with curl and left the response
    # — including a control-plane-generated private key — beside the config. That
    # identity was never usable by the sensor; do not leave its key on disk. A fresh
    # enrolment also must not inherit the previous sensor's certificate.
    rm -f "$INSTALL_DIR/registration-response.json"
    rm -rf "$INSTALL_DIR/certs" "$INSTALL_DIR/data/certs"

    yaml_quote() {
        local s=${1//\\/\\\\}
        s=${s//\"/\\\"}
        printf '"%s"' "$s"
    }

    INTERFACES_YAML=""
    IFS=',' read -ra INTERFACE_ARRAY <<< "$INTERFACES"
    for iface in "${INTERFACE_ARRAY[@]}"; do
        iface="${iface//[[:space:]]/}"
        [[ -z "$iface" ]] && continue
        [[ -n "$INTERFACES_YAML" ]] && INTERFACES_YAML+=", "
        INTERFACES_YAML+=$(yaml_quote "$iface")
    done

    # Holds the registration key until the sensor redeems it: owner-only before any
    # content is written (cat > keeps the mode of the file it truncates).
    : > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    cat > "$CONFIG_FILE" << EOF
# Vista Platform Sensor configuration (generated by install-sensor.sh)
# sensorId holds the sensor's name until it registers, then its UUID.
sensorId: $(yaml_quote "$SENSOR_NAME")
controlPlaneUrl: $(yaml_quote "$CONTROL_PLANE_URL")
registrationKey: $(yaml_quote "$REGISTRATION_KEY")
reportingIntervalSeconds: 30

capture:
  interfaces: [$INTERFACES_YAML]
  activeProbing: true
  networkDiscovery: true

storage:
  dataPath: $(yaml_quote "$INSTALL_DIR/data")
EOF
fi

# Step 6: Create systemd service
print_status "Creating systemd service..."
EXEC_START="$INSTALL_DIR/$INSTALLED_BINARY --verbose -config $CONFIG_FILE"
if [[ -n "$CA_FINGERPRINT" ]]; then
    # Pins the platform's CA on first start, verified against this
    # fingerprint; ignored once a CA is in the config.
    EXEC_START+=" -ca-fingerprint $CA_FINGERPRINT"
fi
cat > "$NEW_UNIT" << EOF
[Unit]
Description=Vista Platform Sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
# The address the operator entered when creating the registration key (--ip),
# already checked to be on this host. Pinning it makes registration report the
# address the platform expects even on a multi-homed host, where the sensor's
# own guess (the source address of its route to the control plane) can differ.
# Remove this line to have the sensor report whatever address it detects.
Environment=SENSOR_IP_ADDRESS=$EXPECTED_IP
# Registers on first start with the key in the config, then runs from the
# certificate it was issued.
ExecStart=$EXEC_START
Restart=always
RestartSec=10
# Exit status 78 (EX_CONFIG) means a person has to act: the registration key was
# rejected, or the config file is unusable. Restarting would only repeat it.
RestartPreventExitStatus=78
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

# Network settings
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# Step 7: Set permissions
# The sensor rewrites its config and writes its certificate under data/, so the
# service user must own both.
print_status "Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chmod 600 "$CONFIG_FILE"

# Step 8: Start the service; the sensor registers itself
print_status "Starting the sensor; it registers itself with the control plane..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME.service"
START_EPOCH=$(date +%s)
if ! systemctl restart "$SERVICE_NAME.service"; then
    print_error "Failed to start sensor service"
    print_status "Check logs with: journalctl -u $SERVICE_NAME -f"
    exit 1
fi
MIGRATION_STEP=""
# The old binary came along with the directory.
if [[ ! "$INSTALL_DIR/$LEGACY_BINARY" -ef "$BINARY" ]]; then
    rm -f "$INSTALL_DIR/$LEGACY_BINARY"
fi

# Step 9: Wait for registration
#
# Registration is confirmed only by the sensor itself: it rewrites sensorId with
# the UUID the platform accepted. A running service is not a registered sensor —
# an unregistered one captures traffic and can submit none of it.
REGISTRATION_TIMEOUT=${REGISTRATION_TIMEOUT:-90}
print_status "Waiting up to ${REGISTRATION_TIMEOUT}s for the sensor to register..."
SENSOR_ID=""
REJECTED=false
while (( $(date +%s) - START_EPOCH < REGISTRATION_TIMEOUT )); do
    current_id=$(read_config_value sensorId "$CONFIG_FILE")
    if [[ "$current_id" =~ $UUID_RE ]]; then
        SENSOR_ID="$current_id"
        break
    fi
    if journalctl -u "$SERVICE_NAME.service" --since "@$START_EPOCH" --no-pager -o cat 2>/dev/null \
        | grep -q 'Registration was REJECTED'; then
        REJECTED=true
        break
    fi
    sleep 2
done

if [[ -z "$SENSOR_ID" ]]; then
    echo ""
    journalctl -u "$SERVICE_NAME.service" --since "@$START_EPOCH" --no-pager -o cat 2>/dev/null \
        | grep -E '⛔|❌|Registration (FAILED|retry failed)' | tail -8 || true
    echo ""
    if [[ "$REJECTED" == "true" ]]; then
        # A rejected key never succeeds; stop the service rather than leave it
        # restarting every 10 seconds.
        systemctl stop "$SERVICE_NAME.service" || true
        systemctl disable "$SERVICE_NAME.service" 2>/dev/null || true
        print_error "The control plane REJECTED the registration key (see above): it is invalid, expired, or already used."
        print_error "Generate a new key (Discovery → Sensors & Agents → Register) and re-run this installer with it."
        print_status "The sensor service has been stopped and disabled."
    else
        print_error "The sensor did not register within ${REGISTRATION_TIMEOUT}s."
        print_status "It is still running and retrying in the background; check that $CONTROL_PLANE_URL is reachable from this host."
        print_status "Watch it with: journalctl -u $SERVICE_NAME -f"
    fi
    exit 1
fi

if ! systemctl is-active --quiet "$SERVICE_NAME.service"; then
    print_error "❌ The sensor registered but is not running"
    print_status "Check logs with: journalctl -u $SERVICE_NAME -f"
    exit 1
fi

# Final status
print_header "🎉 Installation Complete!"
echo "================================"
echo "Sensor Name: $SENSOR_NAME"
echo "Sensor ID: $SENSOR_ID"
echo "Sensor Version: $SENSOR_VERSION"
echo "Installation Directory: $INSTALL_DIR"
echo "Configuration: $CONFIG_FILE"
echo "Service: $SERVICE_NAME.service"
echo "Control Plane: $CONTROL_PLANE_URL"
echo ""
echo "📋 Management Commands:"
echo "  Status:     systemctl status $SERVICE_NAME"
echo "  Logs:       journalctl -u $SERVICE_NAME -f"
echo "  Restart:    systemctl restart $SERVICE_NAME"
echo "  Stop:       systemctl stop $SERVICE_NAME"
echo "  Uninstall:  systemctl stop $SERVICE_NAME && systemctl disable $SERVICE_NAME"
echo ""
print_status "Sensor is registered and monitoring network traffic on: $INTERFACES"
print_status "It appears under Discovery → Sensors & Agents once its first heartbeat arrives."
