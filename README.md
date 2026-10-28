# torctl

`torctl` redirects system traffic, including DNS queries, through the Tor
network. The command-line tool is implemented in Rust and targets Linux
systems using `systemd`, `iptables`, and the standard Tor service.

## Requirements

- Rust 1.74 or newer
- Linux with `systemd` and `iptables`
- Tor installed as the `tor` system service
- `macchanger` for `chngmac` and `rvmac`
- `smem-secure-delete` for `wipe`

The commands that change firewall, service, network, or kernel state must be
run as root.

## Build and installation

```sh
cargo build --release
install -Dm755 target/release/torctl /usr/bin/torctl
install -Dm644 service/torctl-autostart.service /usr/lib/systemd/system/torctl-autostart.service
install -Dm644 service/torctl-autowipe.service /usr/lib/systemd/system/torctl-autowipe.service
install -Dm644 bash-completion/torctl /usr/share/bash-completion/completions/torctl
systemctl daemon-reload
```

## Usage

```text
torctl <COMMAND>

Commands:
  start      Start Tor and redirect all traffic through Tor
  stop       Stop Tor and restore the previous network configuration
  status     Show torctl, Tor, autostart, and autowipe status
  restart    Stop and start torctl
  autowipe   Enable memory wiping at shutdown
  autostart  Enable torctl at startup
  ip         Print the current remote IP address
  chngid     Change the Tor identity
  chngmac    Randomize MAC addresses on all non-loopback interfaces
  rvmac      Restore permanent MAC addresses
  version    Print the torctl version
  wipe       Wipe memory and secure-delete temporary data
```

`start` backs up `/etc/tor/torrc`, `/etc/resolv.conf`, the current iptables
rules, and the sysctl values that torctl changes under `/var/lib/torctl`.
Resolver files are copied without removing the live file, and symlinks are
preserved. If startup fails, torctl restores the changes made during that
attempt; `stop` restores the backups from a successful start. Do not manually
edit or remove that directory while torctl is active.

## Development

```sh
cargo fmt --check
cargo check
```

GitHub Actions runs formatting, Clippy, builds, and tests for pushes and pull
requests. A version tag such as `v0.5.7` validates the crate, creates a draft
GitHub release, uploads Linux binaries for x86_64 and ARM64, publishes the
crate to crates.io, and then publishes the GitHub release. The
`CRATES_IO_TOKEN` repository secret is required for tagged releases.

## License

torctl is distributed under the GNU General Public License, version 3 or later.
