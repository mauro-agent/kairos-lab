# kairos-lab

`kairos-lab` is a small Go CLI for a first-time local Kairos experience.

This project is not meant to replace virtualization software like virt-manager or UTM. It's aimed at users who don't run virtualization software in their day-to-day and want to give Kairos a try.

The second goal of this project is to help the Kairos team deliver workshops and keep the focus on topics related to Kairos, not on the glitches between different host operating systems or different virtualization software out there.

After you've played with kairos-lab, whether you choose to continue your Kairos journey or not, you can run the `cleanup` command to remove any configuration, downloaded packages, or ISO images.

It helps you:

- download a Kairos ISO (`download`)
- boot a Kairos VM with shared networking by default (`start`)
- manage multiple VM disks
- inspect state (`status`)
- clean VM artifacts (`reset`)
- clean everything created by the tool (`cleanup`)

> **Found a bug, or want to request a feature?** Open it on
> [kairos-io/kairos](https://github.com/kairos-io/kairos/issues), including
> issues about this repository. Every Kairos issue lives in one place, so you
> never have to work out which repository to file against.

## Supported Platforms

- macOS
- Linux

Windows is not supported, use your preferred virtualization software to spin up a Kairos VM e.g. VirtualBox. You might be able to run inside WSL but it's not recommended because without KVM support the experience will be terribly slow.

## Install

### macOS (recommended)

```bash
brew tap kairos-io/kairos
brew install kairos-lab
```

### Download Binary

Pre-built binaries are available on the [releases page](https://github.com/kairos-io/kairos-lab/releases).

**Note for macOS:** The binary is not signed. You'll need to authorize it in System Settings > Privacy & Security after the first run. The exact steps vary by macOS version.

### Build from Source

```bash
go build -o kairos-lab ./cmd/kairos-lab
```

## Quick Start

### 1) Setup dependencies (optional)

```bash
./kairos-lab setup
```

Detects your package manager and installs required tools (`qemu`) if missing.

### 2) Download a Kairos ISO

```bash
./kairos-lab download
```

Interactive selection of:
- Image type: `core` (base OS) or `standard` (with K3s)
- K3s version (if standard)

The ISO is saved to the cache directory and tracked for cleanup.

### 3) Start a VM

```bash
./kairos-lab start
```

This will:
- Create a new disk (named after the ISO + timestamp)
- Boot the VM with the ISO attached
- Use shared networking (VM gets a real address on a NAT subnet you can SSH to)
- Open a graphical window
- Poll for the VM's address for up to 45s. While the VM is running that ends
  one of three ways: a usable address prints a WebUI URL and an SSH command; a
  link-local one (169.254.x.x, what a guest assigns itself when no DHCP server
  answers it) prints the same two lines under a heading saying the address is
  link-local, with what to check, since those URLs will not reach the VM; and a
  poll that runs out of time says it has stopped looking. The VM keeps running
  in all three. Quit the VM before any of them and the poll simply stops,
  saying nothing

**Exit the VM with `Ctrl-a x`**

### 4) Boot an installed system

After installing Kairos to the disk, start again:

```bash
./kairos-lab start
```

Select your existing disk - it will boot from disk without the ISO.

## Commands

### `download`

Downloads a Kairos ISO with interactive selection:
- Fetches latest release from GitHub
- Filters by your architecture (amd64/arm64)
- Prompts for core vs standard, K3s version

### `start`

Boots a VM with sensible defaults:
- **Display**: `window` (graphical) by default
- **Network**: `shared` by default (VM gets a real address on a NAT subnet)
- **Disk**: Select existing or create new

Flags:
- `-name <name>` - Use/create disk with specific name
- `-new` - Force create new disk
- `-no-iso` - Boot without ISO (installed system)
- `-iso <path>` - Use specific ISO file
- `-display window|serial` - Display mode (default: window)
- `-network shared|bridged|user` - Network mode (default: shared)
- `-disk-size 60G` - Disk size for new disks
- `-memory 4` / `-cpus 2` - VM resources (memory is in GB, not MB)
- `-yes` - Auto-confirm prompts

### `status`

Shows current state:
- Platform and dependencies
- The ISO and disk path in use
- Network configuration, including the bridge and tap on Linux, where
  `shared` and `bridged` build them (on macOS QEMU's vmnet backend does the
  bridging and there are none to name)
- The VM's address, once one has been found
- Running VM info

### `reset`

Removes VM artifacts:
- Disks (all or specific with `-disk <name>`)
- Network configuration
- Keeps downloaded ISOs and setup

### `cleanup`

Removes everything created by `kairos-lab`:
- All disks and runtime files
- Downloaded ISOs
- Network configuration
- Dependencies installed by the tool (not pre-existing ones)

## Networking

Three modes, picked with `-network`:

- **shared** (the default) attaches no physical interface at all - it puts the
  VM on a private NAT subnet instead. That's also why it works over Wi-Fi,
  where `bridged` often can't: no guest frame leaves the host with a MAC the
  access point never saw associate. The VM still gets a real address on that
  subnet, not just forwarded ports.
- **bridged** puts the VM on your LAN with a real LAN address, at the cost of
  enslaving a physical interface to the bridge.
- **user** is QEMU's own NAT with ports forwarded to localhost. It needs no
  privileges and no NetworkManager, but it supports a single VM and no
  cluster - the guest has no address on your network.

### macOS

Both `shared` and `bridged` use QEMU's vmnet backend and need sudo: Apple
gates the vmnet entitlement to virtualization vendors, so a Homebrew QEMU can
reach it only when it's launched as root. `start` checks for that up front,
before anything is built (no disk image, no bridge, no tap), and refuses if
you can't get it - not in the admin or wheel group, or no sudo binary at all -
rather than fail midway through.

`bridged`'s interface defaults to the one holding the host's default route.
`start` refuses to run when that interface has no link, because vmnet builds
the bridge anyway and the VM then boots with no DHCP lease and no error. Pass
`-bridge-if <iface>` to choose a different one, or use `-network shared` or
`-network user` instead.

Bridging onto Wi-Fi works on some access points and not on others: many reject
frames from a MAC other than the one that associated. `start` prints a warning
when the interface it picked is a Wi-Fi radio. `shared` has no such problem,
since it attaches to no interface at all.

### Linux

Both `shared` and `bridged` require **NetworkManager**, and both build a
bridge (`kairoslab0`) and a tap device for the VM:
- **shared** attaches nothing but the tap. NetworkManager runs a DHCP server
  and NAT on the bridge, so the VM gets an address on a private subnet with no
  physical interface touched. Its connections are created with autoconnect
  off, so `systemctl restart NetworkManager` while a shared VM is running
  takes the bridge and tap down with it, and they only come back on the next
  `start` - the trade for not running a DHCP server, DNS forwarder and NAT
  rule on every boot of a host that has no VM up at all.
- **bridged** also enslaves your physical interface to the bridge, so the VM
  takes its lease from your LAN instead. Its connections autoconnect, so a
  NetworkManager restart brings the bridge back on its own.

If NetworkManager is not available, use `-network user` for port-forwarded access (SSH via `localhost:2222`).

## State and Paths

By default:
- Config/state: `$XDG_CONFIG_HOME/kairos-lab/` (or `~/.config/kairos-lab/`)
- Cache/artifacts: `$XDG_CACHE_HOME/kairos-lab/` (or `~/.cache/kairos-lab/`)

Override with environment variables:
- `KAIROS_LAB_CONFIG_DIR`
- `KAIROS_LAB_CACHE_DIR`

## Safety

- Cleanup only removes what the tool created
- Dependencies that existed before setup are never removed
- Network cleanup reconnects your physical interface after `bridged`, but
  only when it is what deleted the bridge-slave profile that had put the
  interface on the bridge: `nmcli device connect <iface>` activates whichever
  profile NetworkManager rates best for the device, and after a bridged run
  that is routinely the bridge-slave one, so reconnecting while it is still
  there would put the interface straight back on a bridge. When cleanup
  declines, it prints which interface it left alone and how to put it back
  yourself. When it does reconnect, NetworkManager may still pick a different
  profile than your original one. `shared` enslaves no interface, so there is
  nothing to reconnect
- Destructive operations require confirmation (use `-yes` to skip)
