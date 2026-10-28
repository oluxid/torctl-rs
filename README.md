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
rules, and current sysctl values under `/var/lib/torctl`. `stop` restores those
backups. Do not manually edit or remove that directory while torctl is active.

## Development

```sh
cargo fmt --check
cargo check
```

## License

torctl is distributed under the GNU General Public License, version 3 or later.
