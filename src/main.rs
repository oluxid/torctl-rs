use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

const VERSION: &str = concat!("torctl ", env!("CARGO_PKG_VERSION"));
const BACKUP_DIR: &str = "/var/lib/torctl";
const TORRC: &str = "/etc/tor/torrc";
const TOR_UID: &str = "tor";
const TOR_PORT: &str = "9040";
const TOR_DNS: &str = "9053";
const TOR_PASSWORD: &str = "16:FDE8ED505C45C8BA602385E2CA5B3250ED00AC0920FEC1230813A1F86F";

#[derive(Parser)]
#[command(name = "torctl", version = VERSION, about = "Redirect all traffic through the Tor network")]
struct Cli {
    #[command(subcommand)]
    command: Option<CommandKind>,
}

#[derive(Subcommand)]
enum CommandKind {
    Start,
    Stop,
    Status,
    Restart,
    Autowipe,
    Autostart,
    Ip,
    Chngid,
    Chngmac,
    Rvmac,
    Version,
    Wipe,
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("\x1b[31m[-]\x1b[0m ERROR: {error:#}");
        std::process::exit(1);
    }
}

fn execute() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        print_usage();
        bail!("a command is required");
    };

    match command {
        CommandKind::Version => println!("{VERSION}"),
        CommandKind::Ip => get_ip()?,
        CommandKind::Start => privileged(start)?,
        CommandKind::Stop => privileged(stop)?,
        CommandKind::Status => privileged(status)?,
        CommandKind::Restart => privileged(restart)?,
        CommandKind::Autowipe => privileged(|| enable_service("torctl-autowipe"))?,
        CommandKind::Autostart => privileged(|| enable_service("torctl-autostart"))?,
        CommandKind::Chngid => privileged(change_identity)?,
        CommandKind::Chngmac => privileged(|| change_mac(false))?,
        CommandKind::Rvmac => privileged(|| change_mac(true))?,
        CommandKind::Wipe => privileged(wipe)?,
    }
    Ok(())
}

fn privileged<F>(action: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let uid = command_output("id", &["-u"])?;
    if uid.trim() != "0" {
        bail!("this command must be run as root");
    }
    fs::create_dir_all(BACKUP_DIR).context("creating backup directory")?;
    action()
}

fn start() -> Result<()> {
    if started() {
        bail!("torctl is already started");
    }
    backup_file(TORRC, "torrc.bak", "tor config")?;
    backup_file("/etc/resolv.conf", "resolv.conf.bak", "nameservers")?;
    run_to_file(
        "iptables-save",
        &[],
        backup_path("iptables.rules.bak"),
        "iptables rules",
    )?;
    run_to_file(
        "sysctl",
        &["-a"],
        backup_path("sysctl.conf.bak"),
        "sysctl rules",
    )?;
    run("iptables", &["-F"])?;
    run("iptables", &["-t", "nat", "-F"])?;
    write_torrc()?;
    write_resolv_conf()?;
    start_service("tor")?;
    apply_iptables_rules()?;
    apply_sysctl_rules()?;
    msg("all traffic is being redirected through tor");
    fs::write(backup_path("started"), []).context("recording torctl state")?;
    Ok(())
}

fn stop() -> Result<()> {
    if !started() {
        bail!("torctl is already stopped");
    }
    restore_sysctl()?;
    run("iptables", &["-F"])?;
    run("iptables", &["-t", "nat", "-F"])?;
    restore_iptables()?;
    stop_service("tor")?;
    restore_file(TORRC, "torrc.bak", "tor config")?;
    restore_file("/etc/resolv.conf", "resolv.conf.bak", "nameservers")?;
    fs::remove_file(backup_path("started")).ok();
    Ok(())
}

fn restart() -> Result<()> {
    stop()?;
    thread::sleep(Duration::from_secs(1));
    start()
}

fn status() -> Result<()> {
    if started() {
        msg("torctl is started");
    } else {
        warn("torctl is stopped");
    }
    service_state("tor", "tor service", false)?;
    service_state("torctl-autowipe", "torctl-autowipe service", true)?;
    service_state("torctl-autostart", "torctl-autostart service", true)
}

fn change_identity() -> Result<()> {
    if !started() {
        bail!("torctl is stopped");
    }
    info("changing tor identity");
    stop_service("tor")?;
    thread::sleep(Duration::from_secs(1));
    start_service("tor")?;
    msg("tor identity changed");
    Ok(())
}

fn change_mac(revert: bool) -> Result<()> {
    warn(if revert {
        "reverting mac addresses"
    } else {
        "changing mac addresses"
    });
    for entry in fs::read_dir("/sys/class/net").context("listing network interfaces")? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name == "lo" {
            continue;
        }
        run("ip", &["link", "set", &name, "down"])?;
        run("macchanger", &[if revert { "-p" } else { "-r" }, &name])?;
        run("ip", &["link", "set", &name, "up"])?;
    }
    msg(if revert {
        "reverted mac addresses"
    } else {
        "changed mac addresses"
    });
    Ok(())
}

fn wipe() -> Result<()> {
    for (key, value) in [
        ("vm.min_free_kbytes", "1024"),
        ("vm.drop_caches", "3"),
        ("vm.oom_kill_allocating_task", "1"),
        ("vm.overcommit_memory", "1"),
        ("vm.oom_dump_tasks", "0"),
    ] {
        run("sysctl", &["-w", &format!("{key}={value}")])?;
    }
    run("smem-secure-delete", &["-fllv"])
}

fn get_ip() -> Result<()> {
    let ip = reqwest::blocking::get("https://ipinfo.io/ip")
        .context("requesting remote IP")?
        .error_for_status()
        .context("remote IP request failed")?
        .text()
        .context("reading remote IP")?;
    msg(&format!("remote ip: {}", ip.trim()));
    Ok(())
}

fn apply_iptables_rules() -> Result<()> {
    info("applying iptables rules");
    iptables(&[
        "-t",
        "nat",
        "-A",
        "OUTPUT",
        "-m",
        "owner",
        "--uid-owner",
        TOR_UID,
        "-j",
        "RETURN",
    ])?;
    for protocol in ["udp", "tcp"] {
        iptables(&[
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            protocol,
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-ports",
            TOR_DNS,
        ])?;
    }
    iptables(&[
        "-t",
        "nat",
        "-A",
        "OUTPUT",
        "-p",
        "udp",
        "-m",
        "owner",
        "--uid-owner",
        TOR_UID,
        "-m",
        "udp",
        "--dport",
        "53",
        "-j",
        "REDIRECT",
        "--to-ports",
        TOR_DNS,
    ])?;
    for protocol in ["tcp", "udp"] {
        iptables(&[
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            protocol,
            "-d",
            "10.192.0.0/10",
            "-j",
            "REDIRECT",
            "--to-ports",
            TOR_PORT,
        ])?;
    }
    for network in [
        "192.168.0.0/16",
        "172.16.0.0/12",
        "10.0.0.0/8",
        "127.0.0.0/9",
        "127.128.0.0/10",
    ] {
        iptables(&["-t", "nat", "-A", "OUTPUT", "-d", network, "-j", "RETURN"])?;
        iptables(&["-A", "OUTPUT", "-d", network, "-j", "ACCEPT"])?;
    }
    iptables(&[
        "-t",
        "nat",
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "--syn",
        "-j",
        "REDIRECT",
        "--to-ports",
        TOR_PORT,
    ])?;
    iptables(&[
        "-t",
        "nat",
        "-A",
        "OUTPUT",
        "-p",
        "udp",
        "-j",
        "REDIRECT",
        "--to-ports",
        TOR_PORT,
    ])?;
    iptables(&[
        "-t",
        "nat",
        "-A",
        "OUTPUT",
        "-p",
        "icmp",
        "-j",
        "REDIRECT",
        "--to-ports",
        TOR_PORT,
    ])?;
    iptables(&[
        "-A",
        "OUTPUT",
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;
    iptables(&[
        "-A",
        "OUTPUT",
        "-m",
        "owner",
        "--uid-owner",
        TOR_UID,
        "-j",
        "ACCEPT",
    ])?;
    iptables(&["-A", "OUTPUT", "-j", "REJECT"])?;
    msg("applied iptables rules");
    Ok(())
}

fn apply_sysctl_rules() -> Result<()> {
    info("applying sysctl rules");
    let settings = [
        ("net.ipv4.tcp_ecn", "1"),
        ("net.ipv4.tcp_window_scaling", "1"),
        ("net.ipv4.tcp_rmem", "8192 87380 16777216"),
        ("net.ipv4.tcp_wmem", "8192 65536 16777216"),
        ("net.core.rmem_max", "16777216"),
        ("net.core.wmem_max", "16777216"),
        ("net.core.netdev_max_backlog", "16384"),
        ("net.core.dev_weight", "64"),
        ("net.core.somaxconn", "32768"),
        ("net.core.optmem_max", "65535"),
        ("net.ipv4.tcp_max_tw_buckets", "1440000"),
        ("net.ipv4.tcp_tw_reuse", "1"),
        ("net.ipv4.tcp_max_orphans", "16384"),
        ("net.ipv4.tcp_orphan_retries", "0"),
        ("net.ipv4.tcp_no_metrics_save", "1"),
        ("net.ipv4.tcp_moderate_rcvbuf", "1"),
        ("net.unix.max_dgram_qlen", "50"),
        ("net.ipv4.neigh.default.gc_thresh3", "2048"),
        ("net.ipv4.neigh.default.gc_thresh2", "1024"),
        ("net.ipv4.neigh.default.gc_thresh1", "32"),
        ("net.ipv4.neigh.default.gc_interval", "30"),
        ("net.ipv4.neigh.default.proxy_qlen", "96"),
        ("net.ipv4.neigh.default.unres_qlen", "6"),
        ("net.ipv4.tcp_reordering", "3"),
        ("net.ipv4.tcp_retries2", "15"),
        ("net.ipv4.tcp_retries1", "3"),
        ("net.ipv4.tcp_slow_start_after_idle", "0"),
        ("net.ipv4.tcp_fastopen", "3"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("net.ipv4.tcp_rfc1337", "1"),
        ("net.ipv4.conf.default.rp_filter", "1"),
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.default.log_martians", "1"),
        ("net.ipv4.conf.all.log_martians", "1"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0"),
        ("net.ipv4.conf.all.secure_redirects", "0"),
        ("net.ipv4.conf.default.secure_redirects", "0"),
        ("net.ipv6.conf.all.accept_redirects", "0"),
        ("net.ipv6.conf.default.accept_redirects", "0"),
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.default.send_redirects", "0"),
        ("net.ipv4.icmp_echo_ignore_all", "1"),
        ("net.ipv6.conf.all.disable_ipv6", "1"),
        ("net.ipv6.conf.default.disable_ipv6", "1"),
    ];
    for (key, value) in settings {
        run("sysctl", &["-w", &format!("{key}={value}")])?;
    }
    for key in ["net.ipv4.route.flush", "net.ipv6.route.flush"] {
        run("sysctl", &["-w", &format!("{key}=1")])?;
    }
    msg("applied sysctl rules");
    Ok(())
}

fn write_torrc() -> Result<()> {
    let config = format!("# generated by torctl\nUser {TOR_UID}\nDataDirectory /var/lib/tor\nVirtualAddrNetwork 10.192.0.0/10\nAutomapHostsOnResolve 1\nAutomapHostsSuffixes .exit,.onion\nTransPort 127.0.0.1:{TOR_PORT} IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr\nSocksPort 127.0.0.1:9050 IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr\nControlPort 9051\nHashedControlPassword {TOR_PASSWORD}\nDNSPort 127.0.0.1:{TOR_DNS}\nHardwareAccel 1\nTestSocks 1\nAllowNonRFC953Hostnames 0\nWarnPlaintextPorts 23,109,110,143,80\nClientRejectInternalAddresses 1\nNewCircuitPeriod 40\nMaxCircuitDirtiness 600\nMaxClientCircuitsPending 48\nUseEntryGuards 1\nEnforceDistinctSubnets 1\n");
    fs::write(TORRC, config).context("writing tor config")
}

fn write_resolv_conf() -> Result<()> {
    fs::write("/etc/resolv.conf", "# generated by torctl\nnameserver 127.0.0.1\nnameserver 1.1.1.1\nnameserver 1.0.0.1\nnameserver 208.67.222.222\nnameserver 208.67.220.220\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n").context("writing resolv.conf")
}

fn backup_file(source: &str, name: &str, description: &str) -> Result<()> {
    warn(&format!("backing up {description}"));
    fs::rename(source, backup_path(name)).with_context(|| format!("backing up {source}"))?;
    msg(&format!("backed up {description}"));
    Ok(())
}

fn restore_file(destination: &str, name: &str, description: &str) -> Result<()> {
    let backup = backup_path(name);
    if Path::new(&backup).exists() {
        warn(&format!("restoring {description}"));
        let _ = fs::remove_file(destination);
        fs::rename(&backup, destination).with_context(|| format!("restoring {destination}"))?;
        msg(&format!("restored {description}"));
    }
    Ok(())
}

fn restore_iptables() -> Result<()> {
    let path = backup_path("iptables.rules.bak");
    if Path::new(&path).exists() {
        warn("restoring iptables rules");
        run_with_stdin("iptables-restore", &[], &path)?;
        fs::remove_file(path)?;
        msg("restored iptables rules");
    }
    Ok(())
}

fn restore_sysctl() -> Result<()> {
    let path = backup_path("sysctl.conf.bak");
    if Path::new(&path).exists() {
        warn("restoring sysctl rules");
        run(
            "sysctl",
            &["-p", path.to_str().context("invalid sysctl backup path")?],
        )?;
        fs::remove_file(path)?;
        msg("restored sysctl rules");
    }
    Ok(())
}

fn start_service(service: &str) -> Result<()> {
    if systemctl_state(service, "is-active")? == "active" {
        warn(&format!("{service} is running"));
        run("systemctl", &["reload", service])?;
        msg(&format!("reloaded {service} service"));
    } else {
        warn(&format!("{service} is not started"));
        info(&format!("starting {service} service"));
        run("systemctl", &["start", service])?;
        msg(&format!("started {service} service"));
    }
    Ok(())
}

fn stop_service(service: &str) -> Result<()> {
    if systemctl_state(service, "is-active")? == "active" {
        warn(&format!("{service} is active"));
        run("systemctl", &["stop", service])?;
        msg(&format!("stopped {service} service"));
    }
    Ok(())
}

fn enable_service(service: &str) -> Result<()> {
    warn(&format!("enabling {service}"));
    run("systemctl", &["enable", service])?;
    msg(&format!("enabled {service}"));
    Ok(())
}

fn service_state(service: &str, label: &str, enabled: bool) -> Result<()> {
    let query = if enabled { "is-enabled" } else { "is-active" };
    let state = systemctl_state(service, query)?;
    let good = if enabled {
        state == "enabled"
    } else {
        state == "active"
    };
    if good {
        msg(&format!("{label} is: {state}"));
    } else {
        warn(&format!("{label} is: {state}"));
    }
    Ok(())
}

fn systemctl_state(service: &str, query: &str) -> Result<String> {
    let output = Command::new("systemctl")
        .args([query, service])
        .output()
        .with_context(|| format!("querying {service} state"))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("running {program}"))?;
    if !status.success() {
        bail!("{program} failed with {status}");
    }
    Ok(())
}

fn run_to_file(program: &str, args: &[&str], path: PathBuf, description: &str) -> Result<()> {
    info(&format!("backing up {description}"));
    let file = fs::File::create(path)?;
    let status = Command::new(program).args(args).stdout(file).status()?;
    if !status.success() {
        bail!("{program} failed with {status}");
    }
    Ok(())
}

fn run_with_stdin(program: &str, args: &[&str], path: &Path) -> Result<()> {
    let input = fs::File::open(path)?;
    let status = Command::new(program).args(args).stdin(input).status()?;
    if !status.success() {
        bail!("{program} failed with {status}");
    }
    Ok(())
}

fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if !output.status.success() {
        bail!("{program} failed with {}", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn iptables(args: &[&str]) -> Result<()> {
    run("iptables", args)
}
fn backup_path(name: &str) -> PathBuf {
    Path::new(BACKUP_DIR).join(name)
}
fn started() -> bool {
    Path::new(&backup_path("started")).exists()
}
fn msg(text: &str) {
    println!("\x1b[32m[+]\x1b[0m {text}");
}
fn warn(text: &str) {
    println!("\x1b[33m[!]\x1b[0m WARNING: {text}");
}
fn info(text: &str) {
    println!("\x1b[34m[*]\x1b[0m {text}");
}
fn print_usage() {
    println!("Usage: torctl COMMAND\n\nCommands: start stop status restart autowipe autostart ip chngid chngmac rvmac version wipe");
}
