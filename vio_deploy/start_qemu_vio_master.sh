#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  ./start_qemu_vio_master.sh [--config FILE]

This script starts qemu-VIO:
  SNOOP uses SVQ, PASSTHROUGH disables SVQ, and the mode is selected by
  the VIO IOPS threshold state machine.

Config:
  By default, the script reads ./vio_master.conf if it exists.
  Use --config FILE to choose another config file.
  Environment variables override values from the config file.

Examples:
  cp vio_master.conf.example vio_master.conf
  vim vio_master.conf
  ./start_qemu_vio_master.sh

  ./start_qemu_vio_master.sh --config ./vio_master.conf

  VIO_QEMU=/path/to/qemu-system-aarch64 \
  VM_IMAGE=/path/to/guest.qcow2 \
  VHOSTDEV=/dev/vhost-vdpa-0 \
  ./start_qemu_vio_master.sh
EOF
}

CONFIG_FILE=./vio_master.conf

while [[ $# -gt 0 ]]; do
    case "$1" in
    -h|--help)
        usage
        exit 0
        ;;
    --config)
        if [[ $# -lt 2 ]]; then
            echo "--config requires a file path" >&2
            exit 1
        fi
        CONFIG_FILE=$2
        shift 2
        ;;
    *)
        echo "Unknown argument: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
done

env_or_config() {
    local name=$1
    local default_value=$2

    if [[ -n "${!name+x}" ]]; then
        printf '%s\n' "${!name}"
        return
    fi
    if [[ -n "${CONFIG_VALUE[$name]+x}" ]]; then
        printf '%s\n' "${CONFIG_VALUE[$name]}"
        return
    fi
    printf '%s\n' "$default_value"
}

declare -A CONFIG_VALUE=()
if [[ -f "$CONFIG_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line%%#*}
        line=${line#"${line%%[![:space:]]*}"}
        line=${line%"${line##*[![:space:]]}"}
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            key=${BASH_REMATCH[1]}
            value=${BASH_REMATCH[2]}
            value=${value#"${value%%[![:space:]]*}"}
            value=${value%"${value##*[![:space:]]}"}
            value=${value%\"}
            value=${value#\"}
            value=${value%\'}
            value=${value#\'}
            CONFIG_VALUE[$key]=$value
        else
            echo "Invalid config line in $CONFIG_FILE: $line" >&2
            exit 1
        fi
    done < "$CONFIG_FILE"
elif [[ "$CONFIG_FILE" != "./vio_master.conf" ]]; then
    echo "Config file does not exist: $CONFIG_FILE" >&2
    exit 1
fi

VIO_QEMU=$(env_or_config VIO_QEMU /home/zyj/qemu-VIO/build/qemu-system-aarch64)
VM_IMAGE=$(env_or_config VM_IMAGE /home/zyj/ubuntu-arm64/test-vdpa.qcow2)
BIOS=$(env_or_config BIOS /usr/share/edk2/aarch64/QEMU_EFI.fd)
VHOSTDEV=$(env_or_config VHOSTDEV /dev/vhost-vdpa-0)
VIO_VDPA_DEV=$(env_or_config VIO_VDPA_DEV vdpa0)
TASKSET_CPUS=$(env_or_config TASKSET_CPUS 4,5,6,7)
VM_MEM=$(env_or_config VM_MEM 4096)
VM_SMP=$(env_or_config VM_SMP 4)
VM_MAC=$(env_or_config VM_MAC 52:54:00:cb:45:11)
QUEUES=$(env_or_config QUEUES 4)
QEMU_LOG=$(env_or_config QEMU_LOG ./logs/qemu-vio.log)
CONSOLE_LOG=$(env_or_config CONSOLE_LOG ./logs/qemu-console.log)

VIO_DEBUG_TOUCH=$(env_or_config VIO_DEBUG_TOUCH 1)
VIO_HIGH_IOPS=$(env_or_config VIO_HIGH_IOPS 100000)
VIO_LOW_IOPS=$(env_or_config VIO_LOW_IOPS 20000)
VIO_WINDOW_NS=$(env_or_config VIO_WINDOW_NS 1000000000)
VIO_COOLDOWN_NS=$(env_or_config VIO_COOLDOWN_NS 3000000000)
VIO_PASSTHROUGH_MIN_NS=$(env_or_config VIO_PASSTHROUGH_MIN_NS 10000000000)
VIO_PASSTHROUGH_WARMUP_WINDOWS=$(env_or_config VIO_PASSTHROUGH_WARMUP_WINDOWS 2)
VIO_LOW_WINDOWS=$(env_or_config VIO_LOW_WINDOWS 5)
VIO_STATS_STABILIZE_WINDOWS=$(env_or_config VIO_STATS_STABILIZE_WINDOWS 2)
VIO_DEBUG_STATS=$(env_or_config VIO_DEBUG_STATS 0)

check_file() {
    local path=$1
    local name=$2

    if [[ ! -e "$path" ]]; then
        echo "$name does not exist: $path" >&2
        exit 1
    fi
}

check_file "$VIO_QEMU" "QEMU binary"
check_file "$VM_IMAGE" "VM image"
check_file "$BIOS" "BIOS"
check_file "$VHOSTDEV" "vhost-vdpa device"

echo "Starting qemu-VIO"
echo "Config file : $CONFIG_FILE"
echo "QEMU binary : $VIO_QEMU"
echo "VM image    : $VM_IMAGE"
echo "BIOS        : $BIOS"
echo "vhostdev    : $VHOSTDEV"
echo "QEMU log    : $QEMU_LOG"
echo "Console log : $CONSOLE_LOG"

mkdir -p "$(dirname "$QEMU_LOG")" "$(dirname "$CONSOLE_LOG")"
: > "$QEMU_LOG"
: > "$CONSOLE_LOG"

NETDEV_ARG="vhost-vdpa,vhostdev=$VHOSTDEV,id=n0,queues=$QUEUES,x-svq=on"

exec taskset -c "$TASKSET_CPUS" sudo env \
    VIO_DEBUG_TOUCH="$VIO_DEBUG_TOUCH" \
    VIO_VDPA_THRESHOLD=1 \
    VIO_HIGH_IOPS="$VIO_HIGH_IOPS" \
    VIO_LOW_IOPS="$VIO_LOW_IOPS" \
    VIO_WINDOW_NS="$VIO_WINDOW_NS" \
    VIO_COOLDOWN_NS="$VIO_COOLDOWN_NS" \
    VIO_PASSTHROUGH_MIN_NS="$VIO_PASSTHROUGH_MIN_NS" \
    VIO_PASSTHROUGH_WARMUP_WINDOWS="$VIO_PASSTHROUGH_WARMUP_WINDOWS" \
    VIO_LOW_WINDOWS="$VIO_LOW_WINDOWS" \
    VIO_STATS_STABILIZE_WINDOWS="$VIO_STATS_STABILIZE_WINDOWS" \
    VIO_DEBUG_STATS="$VIO_DEBUG_STATS" \
    VIO_VDPA_DEV="$VIO_VDPA_DEV" \
    "$VIO_QEMU" \
        -accel kvm \
        -machine virt,memory-backend=mem1 \
        -cpu host \
        -smp "$VM_SMP" \
        -m "$VM_MEM" \
        -object memory-backend-ram,id=mem1,size="${VM_MEM}M",share=on,prealloc=yes \
        -bios "$BIOS" \
        -drive if=virtio,format=qcow2,file="$VM_IMAGE" \
        -netdev "$NETDEV_ARG" \
        -device virtio-net-pci,netdev=n0,mac="$VM_MAC",mq=on,vectors=10,iommu_platform=on,disable-legacy=on,page-per-vq=on \
        -nographic \
        -d guest_errors \
        -D "$QEMU_LOG" \
        2>&1 | tee "$CONSOLE_LOG"
