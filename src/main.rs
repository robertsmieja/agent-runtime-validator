// agent-runtime-validator (arv)
// Harness-agnostic validation gate for hardened agent runtime images.
// Automates the 26-probe verification runbook (runner-research package).
// Any FAIL exits nonzero and blocks the image.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Stdio};

const DEFAULT_CONFIG: &str = include_str!("../config/default.toml");

// ---------- config ----------

#[derive(Deserialize)]
struct Config {
    meta: Meta,
    target: Target,
    egress: Egress,
    privilege: Privilege,
    #[serde(default)]
    jail: Jail,
    #[serde(default)]
    sandbox: Sandbox,
    #[serde(default)]
    account: Account,
    secrets: Secrets,
    resources: Resources,
    audit: AuditCfg,
    signing: Signing,
}

#[derive(Deserialize)]
struct Meta {
    #[serde(default = "one")]
    config_version: u32,
}
fn one() -> u32 {
    1
}

#[derive(Deserialize)]
struct Target {
    #[serde(default = "default_work_dir")]
    work_dir: String,
}
fn default_work_dir() -> String {
    "/tmp/arv-work".into()
}

#[derive(Deserialize)]
struct Egress {
    #[serde(default = "five")]
    timeout_secs: u64,
    #[serde(default)]
    deny_urls: Vec<String>,
    #[serde(default = "yes")]
    allow_enabled: bool,
    #[serde(default)]
    allow_urls: Vec<String>,
    #[serde(default)]
    dns_direct_server: Option<String>,
    #[serde(default)]
    dns_resolver_name: Option<String>,
    #[serde(default)]
    dns_nxdomain_name: Option<String>,
}
fn five() -> u64 {
    5
}
fn yes() -> bool {
    true
}

#[derive(Deserialize)]
struct Privilege {
    #[serde(default = "yes")]
    sudo_expected: bool,
    #[serde(default = "yes")]
    nft_check: bool,
    #[serde(default)]
    route_test_via: Option<String>,
    #[serde(default)]
    remount_paths: Vec<String>,
    #[serde(default)]
    suid_allowlist: Vec<String>,
    // 27: require the validator runs as a non-root user with no effective caps.
    #[serde(default)]
    require_non_root: bool,
    // 28: bubblewrap must exist AND actually construct a sandbox.
    #[serde(default)]
    check_bwrap: bool,
    // 29: Landlock must appear in the kernel LSM list.
    #[serde(default)]
    check_landlock: bool,
}

#[derive(Deserialize)]
struct Sandbox {
    // 31: own process must run under seccomp with filter level >= min_seccomp
    // (0 disables; 1 = strict, 2 = seccomp-bpf filter). The validator is
    // expected to be launched INSIDE the agent's confinement, so its own
    // /proc/self/status reflects what the harness applies.
    #[serde(default = "default_min_seccomp")]
    min_seccomp: u8,
    // 32: named systemd unit must expose exactly these effective properties
    // (entries of the form "ProtectSystem=strict"; compared verbatim).
    #[serde(default)]
    systemd_unit: Option<String>,
    #[serde(default)]
    systemd_required_props: Vec<String>,
    // Query the user manager (systemctl --user) rather than the system one.
    #[serde(default = "yes")]
    systemd_user: bool,
    // 33: an AppArmor/SELinux profile must be attached (attr/current not
    // "unconfined").
    #[serde(default)]
    require_mac_profile: bool,
    // 34: own process must have NoNewPrivs=1.
    #[serde(default)]
    require_no_new_privs: bool,
}
impl Default for Sandbox {
    fn default() -> Self {
        Sandbox {
            min_seccomp: default_min_seccomp(),
            systemd_unit: None,
            systemd_required_props: Vec::new(),
            systemd_user: true,
            require_mac_profile: false,
            require_no_new_privs: false,
        }
    }
}
fn default_min_seccomp() -> u8 {
    2
}

#[derive(Deserialize)]
struct Account {
    // 35: expected Unix account running the harness. When set, the current
    // user must match exactly.
    #[serde(default)]
    expected_user: Option<String>,
    // 35: exact UID (when set).
    #[serde(default)]
    expected_uid: Option<u32>,
    // 35: group memberships that FAIL the gate.
    #[serde(default = "default_deny_groups")]
    deny_groups: Vec<String>,
    // 35: password must be locked (passwd -S reports 'L') so the account
    // cannot be logged into directly.
    #[serde(default = "yes")]
    require_locked_password: bool,
    // 35: expected login shell (empty = skip).
    #[serde(default)]
    expected_shell: String,
    // 35: home directory mode must be one of these octal strings.
    #[serde(default = "default_home_modes")]
    home_modes: Vec<String>,
    // 35: ~/.ssh/authorized_keys must be absent (empty allowlist skips).
    #[serde(default = "yes")]
    require_no_authorized_keys: bool,
}
fn default_deny_groups() -> Vec<String> {
    ["sudo", "wheel", "root", "docker", "adm"]
        .into_iter()
        .map(String::from)
        .collect()
}
fn default_home_modes() -> Vec<String> {
    ["700", "750"].into_iter().map(String::from).collect()
}
impl Default for Account {
    fn default() -> Self {
        Account {
            expected_user: None,
            expected_uid: None,
            deny_groups: default_deny_groups(),
            require_locked_password: true,
            expected_shell: String::new(),
            home_modes: default_home_modes(),
            require_no_authorized_keys: true,
        }
    }
}

#[derive(Deserialize, Default)]
struct Jail {
    // 30: each path is attempted; writes OUTSIDE allowed roots must FAIL,
    // a write inside the target work_dir must SUCCEED.
    #[serde(default)]
    deny_write_paths: Vec<String>,
    #[serde(default)]
    allow_write_paths: Vec<String>,
}

#[derive(Deserialize)]
struct Secrets {
    #[serde(default = "default_env_pattern")]
    env_substrings: Vec<String>,
    #[serde(default)]
    env_allowlist: Vec<String>,
    #[serde(default)]
    forbidden_paths: Vec<String>,
    #[serde(default)]
    env_file: Option<String>,
    #[serde(default)]
    git_push_dir: Option<String>,
    #[serde(default = "default_push_args")]
    git_push_args: Vec<String>,
}
fn default_env_pattern() -> Vec<String> {
    vec!["key", "token", "secret", "password", "credential"]
        .into_iter()
        .map(String::from)
        .collect()
}
fn default_push_args() -> Vec<String> {
    vec!["push", "origin", "main"]
        .into_iter()
        .map(String::from)
        .collect()
}

#[derive(Deserialize)]
struct Resources {
    #[serde(default = "default_scope_name")]
    scope_name: String,
    #[serde(default = "default_limit_subs")]
    limit_substrings: Vec<String>,
    #[serde(default = "default_fallocate")]
    fallocate_gib: u64,
    #[serde(default)]
    scope_runner_cmd: Option<String>,
    #[serde(default = "default_timeout")]
    scope_timeout_secs: u64,
}
fn default_scope_name() -> String {
    "agent".into()
}
fn default_limit_subs() -> Vec<String> {
    vec!["MemoryMax", "TasksMax", "CPUQuota"]
        .into_iter()
        .map(String::from)
        .collect()
}
fn default_fallocate() -> u64 {
    999
}
fn default_timeout() -> u64 {
    60
}

#[derive(Deserialize)]
struct AuditCfg {
    #[serde(default = "default_exec_probe")]
    exec_probe_cmd: String,
    #[serde(default)]
    collector_log_cmd: Option<String>,
    #[serde(default = "default_canary_url")]
    canary_url: String,
    #[serde(default = "default_canary_env")]
    canary_token_env: String,
}
fn default_exec_probe() -> String {
    "bash -c 'echo hi'".into()
}
fn default_canary_url() -> String {
    "https://gateway.internal/v1".into()
}
fn default_canary_env() -> String {
    "ARV_CANARY_TOKEN".into()
}

#[derive(Deserialize)]
struct Signing {
    #[serde(default)]
    registry_ref: Option<String>,
    #[serde(default)]
    cosign_key: Option<String>,
}

// ---------- probe framework ----------

// PASS/FAIL/SKIP are the runbook's domain terms, kept as-is.
#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Clone, Copy, PartialEq)]
enum Status {
    PASS,
    FAIL,
    SKIP,
}

#[derive(Serialize, Clone)]
struct ProbeResult {
    id: u32,
    section: &'static str,
    name: &'static str,
    status: Status,
    detail: String,
}

struct Ctx {
    is_admin: bool,
    destructive: bool,
    home: String,
}

fn sh(cmd: &str) -> (Option<i32>, String) {
    match Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .output()
    {
        Ok(o) => (
            o.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
        ),
        Err(e) => (None, format!("spawn error: {e}")),
    }
}

fn expand(p: &str, home: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if p == "~" {
        home.to_string()
    } else {
        p.to_string()
    }
}

fn net_probe(
    results: &mut Vec<ProbeResult>,
    _ctx: &Ctx, // reserved for per-context gating (e.g. expected agent user)
    cfg: &Egress,
    url: &str,
    expect_success: bool,
    id: u32,
) {
    let t = cfg.timeout_secs;
    let (code, out) = sh(&format!("curl -sS -m {t} -o /dev/null {}", shellq(url)));
    let ok = code == Some(0);
    let pass = ok == expect_success;
    results.push(ProbeResult {
        id,
        section: "egress",
        name: if expect_success { "allow" } else { "deny" },
        status: if pass { Status::PASS } else { Status::FAIL },
        detail: format!(
            "url={url} curl_exit={} (expected {})",
            code.map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into()),
            if expect_success { "success" } else { "fail" }
        ) + &trunc(&out, 160),
    });
}

fn shellq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn trunc(s: &str, n: usize) -> String {
    let s = s.trim().replace('\n', " | ");
    if s.len() > n {
        // Back off to the nearest char boundary so multibyte output
        // (curl/journalctl messages in any locale) can't panic the gate.
        let mut end = n;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!(" :: {}…", &s[..end])
    } else if !s.is_empty() {
        format!(" :: {s}")
    } else {
        String::new()
    }
}

fn skip(
    results: &mut Vec<ProbeResult>,
    id: u32,
    section: &'static str,
    name: &'static str,
    why: &str,
) {
    results.push(ProbeResult {
        id,
        section,
        name,
        status: Status::SKIP,
        detail: why.into(),
    });
}

/// Runbook deny URLs: #1 = first, #3/#4 = next two (runbook numbering).
/// URLs beyond the runbook get IDs above 40 so they can never collide
/// with the fixed probe IDs 5-35.
fn deny_probe_id(i: u32) -> u32 {
    match i {
        0 => 1,
        1 => 3,
        2 => 4,
        n => 40 + n,
    }
}

/// Runbook allow URL is #2; extra allow URLs get IDs above 50.
fn allow_probe_id(i: u32) -> u32 {
    if i == 0 {
        2
    } else {
        50 + i
    }
}

/// Component-wise path containment. A string prefix match would wrongly
/// treat /tmp/arv-work-backup as "inside" /tmp/arv-work.
fn path_is_under(child: &str, parent: &str) -> bool {
    std::path::Path::new(child).starts_with(parent)
}

// ---------- probe suite (runbook order) ----------

fn run_probes(cfg: &Config, ctx: &Ctx, only: Option<&str>) -> Vec<ProbeResult> {
    let mut r: Vec<ProbeResult> = Vec::new();
    let add = |r: &mut Vec<ProbeResult>, res: ProbeResult| {
        if only.map(|s| res.section == s).unwrap_or(true) {
            r.push(res);
        }
    };
    let in_scope = |section: &'static str| only.map(|s| section == s).unwrap_or(true);

    // --- Egress ---
    if in_scope("egress") {
        let eg = &cfg.egress;
        for (i, url) in eg.deny_urls.iter().enumerate() {
            net_probe(&mut r, ctx, eg, url, false, deny_probe_id(i as u32));
        }
        if eg.allow_enabled {
            for (i, url) in eg.allow_urls.iter().enumerate() {
                net_probe(&mut r, ctx, eg, url, true, allow_probe_id(i as u32));
            }
        } else {
            skip(
                &mut r,
                2,
                "egress",
                "allow",
                "allow_enabled=false for this task class",
            );
        }
        // Probe 5: direct DNS to external resolver must fail
        if let Some(server) = &eg.dns_direct_server {
            let (code, out) = sh(&format!(
                "dig +time=3 +tries=1 @{} evil.example",
                shellq(server)
            ));
            add(
                &mut r,
                ProbeResult {
                    id: 5,
                    section: "egress",
                    name: "dns_direct_deny",
                    status: if code != Some(0) {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!("dig @{server} exit={:?}{}", code, trunc(&out, 120)),
                },
            );
        } else {
            skip(
                &mut r,
                5,
                "egress",
                "dns_direct_deny",
                "dns_direct_server not configured",
            );
        }
        // Probe 6: resolution via local resolver must succeed
        if let Some(name) = &eg.dns_resolver_name {
            let (code, out) = sh(&format!("dig +time=3 +tries=1 {}", shellq(name)));
            // CNAME chains legitimately produce multiple answer records.
            let answers = out
                .lines()
                .find(|l| l.contains("ANSWER:"))
                .and_then(|l| l.split("ANSWER:").nth(1))
                .and_then(|rest| rest.split(',').next())
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(0);
            let ok = code == Some(0) && out.contains("status: NOERROR") && answers >= 1;
            add(
                &mut r,
                ProbeResult {
                    id: 6,
                    section: "egress",
                    name: "dns_via_resolver",
                    status: if ok { Status::PASS } else { Status::FAIL },
                    detail: format!("dig {name} exit={:?}{}", code, trunc(&out, 120)),
                },
            );
        } else {
            skip(
                &mut r,
                6,
                "egress",
                "dns_via_resolver",
                "dns_resolver_name not configured",
            );
        }
        // Probe 7: non-allowlisted name must NXDOMAIN/REFUSED
        if let Some(name) = &eg.dns_nxdomain_name {
            let (code, out) = sh(&format!("dig +time=3 +tries=1 {}", shellq(name)));
            let refused = out.contains("status: NXDOMAIN") || out.contains("status: REFUSED");
            let ok = refused || code != Some(0);
            add(
                &mut r,
                ProbeResult {
                    id: 7,
                    section: "egress",
                    name: "dns_nxdomain",
                    status: if ok { Status::PASS } else { Status::FAIL },
                    detail: format!("dig {name} exit={:?}{}", code, trunc(&out, 120)),
                },
            );
        } else {
            skip(
                &mut r,
                7,
                "egress",
                "dns_nxdomain",
                "dns_nxdomain_name not configured",
            );
        }
    }

    // --- Privilege ---
    if in_scope("privilege") {
        let pv = &cfg.privilege;
        // 8: no passwordless sudo
        if !pv.sudo_expected {
            let (code, out) = sh("sudo -n true");
            add(
                &mut r,
                ProbeResult {
                    id: 8,
                    section: "privilege",
                    name: "no_sudo",
                    status: if code != Some(0) {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!("sudo -n true exit={:?}{}", code, trunc(&out, 120)),
                },
            );
        }
        // 9: nft ruleset unreadable
        if pv.nft_check {
            let (code, out) = sh("nft list ruleset");
            add(
                &mut r,
                ProbeResult {
                    id: 9,
                    section: "privilege",
                    name: "nft_denied",
                    status: if code != Some(0) {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!("nft list ruleset exit={:?}{}", code, trunc(&out, 120)),
                },
            );
        }
        // 10: no CAP_NET_ADMIN
        if let Some(via) = &pv.route_test_via {
            let (code, out) = sh(&format!("ip route add 10.9.9.9/32 via {}", shellq(via)));
            if code == Some(0) {
                // The command "succeeding" means the control is missing (FAIL).
                // Roll the route back so a misconfigured image isn't left mutated.
                let _ = sh("ip route del 10.9.9.9/32");
            }
            add(
                &mut r,
                ProbeResult {
                    id: 10,
                    section: "privilege",
                    name: "no_net_admin",
                    status: if code != Some(0) {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!("ip route add exit={:?}{}", code, trunc(&out, 120)),
                },
            );
        } else {
            skip(
                &mut r,
                10,
                "privilege",
                "no_net_admin",
                "route_test_via not configured",
            );
        }
        // 11: harness tree immutable
        for path in &pv.remount_paths {
            let p = expand(path, &ctx.home);
            let (code, out) = sh(&format!("mount -o remount,rw {}", shellq(&p)));
            if code == Some(0) {
                // Control missing (FAIL): restore read-only before reporting.
                let _ = sh(&format!("mount -o remount,ro {}", shellq(&p)));
            }
            add(
                &mut r,
                ProbeResult {
                    id: 11,
                    section: "privilege",
                    name: "remount_denied",
                    status: if code != Some(0) {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!("remount,rw {p} exit={:?}{}", code, trunc(&out, 120)),
                },
            );
        }
        // 12: exact suid set. Scan every local filesystem (df -l), not just /,
        // so suid binaries on separate mounts can't hide behind -xdev.
        let (_, df_out) = sh("df -l --output=target 2>/dev/null");
        let mut targets: Vec<String> = vec!["/".into()];
        for line in df_out.lines().skip(1) {
            let t = line.trim();
            if !t.is_empty() && !targets.iter().any(|x| x == t) {
                targets.push(t.to_string());
            }
        }
        let mut found: Vec<String> = Vec::new();
        for t in &targets {
            let (_, out) = sh(&format!(
                "find {} -xdev -perm -4000 -user root 2>/dev/null",
                shellq(t)
            ));
            found.extend(
                out.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(String::from),
            );
        }
        found.sort();
        found.dedup();
        let allow: Vec<&str> = pv.suid_allowlist.iter().map(String::as_str).collect();
        let extra: Vec<&str> = found
            .iter()
            .map(String::as_str)
            .filter(|b| !allow.contains(b))
            .collect();
        let missing: Vec<&str> = allow
            .iter()
            .copied()
            .filter(|b| !found.iter().any(|f| f == b))
            .collect();
        let ok = extra.is_empty() && missing.is_empty();
        add(
            &mut r,
            ProbeResult {
                id: 12,
                section: "privilege",
                name: "suid_exact_set",
                status: if ok { Status::PASS } else { Status::FAIL },
                detail: format!(
                    "found={} extra={:?} missing_from_image={:?} scanned={:?}",
                    found.len(),
                    extra,
                    missing,
                    targets
                ),
            },
        );
        // 27: non-root user with no effective capabilities
        if pv.require_non_root {
            let uid_v = uid();
            let caps = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("CapEff:"))
                        .map(|l| l.split_whitespace().last().unwrap_or("?").to_string())
                })
                .unwrap_or_else(|| "?".into());
            let no_caps = caps == "0000000000000000";
            let ok27 = uid_v != 0 && no_caps;
            add(
                &mut r,
                ProbeResult {
                    id: 27,
                    section: "privilege",
                    name: "non_root_no_caps",
                    status: if ok27 { Status::PASS } else { Status::FAIL },
                    detail: format!(
                        "uid={} CapEff={} (need uid!=0 and zero effective caps)",
                        uid_v, caps
                    ),
                },
            );
        }
        // 28: bubblewrap constructs a real sandbox
        if pv.check_bwrap {
            let (code, out) = sh("bwrap --ro-bind / / --proc /proc --dev /dev --unshare-all true");
            let bwrap_ok = code == Some(0);
            // userns availability explains most bwrap failures
            let userns_exit = sh("unshare --user --map-root-user true").0;
            add(
                &mut r,
                ProbeResult {
                    id: 28,
                    section: "privilege",
                    name: "bwrap_sandbox",
                    status: if bwrap_ok { Status::PASS } else { Status::FAIL },
                    detail: format!(
                        "bwrap exit={:?} userns_exit={:?}{}",
                        code,
                        userns_exit,
                        if bwrap_ok {
                            String::new()
                        } else {
                            trunc(&out, 160)
                        }
                    ),
                },
            );
        }
        // 29: Landlock active in kernel LSM list
        if pv.check_landlock {
            let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
            let has = lsm.split(',').any(|s| s.trim() == "landlock");
            add(
                &mut r,
                ProbeResult {
                    id: 29,
                    section: "privilege",
                    name: "landlock_kernel",
                    status: if has { Status::PASS } else { Status::FAIL },
                    detail: if lsm.is_empty() {
                        "/sys/kernel/security/lsm unreadable (securityfs not mounted?)".into()
                    } else {
                        format!("lsm list: {}", lsm.trim())
                    },
                },
            );
        }
        // 30: filesystem jail — writes outside allowed roots fail, inside succeed
        if !cfg.jail.deny_write_paths.is_empty() || !cfg.jail.allow_write_paths.is_empty() {
            let mut jail_fail = false;
            let mut details: Vec<String> = Vec::new();
            for path in cfg
                .jail
                .deny_write_paths
                .iter()
                .chain(cfg.jail.allow_write_paths.iter())
            {
                let p = expand(path, &ctx.home);
                let allowed = cfg
                    .jail
                    .allow_write_paths
                    .iter()
                    .any(|a| path_is_under(&p, &expand(a, &ctx.home)));
                if allowed {
                    let _ = std::fs::create_dir_all(&p);
                }
                let probe = format!("{}/arv-probe-{}", p, std::process::id());
                if !std::path::Path::new(&p).is_dir() {
                    // Fail closed: a configured jail path we cannot evaluate
                    // must not silently count as blocked.
                    details.push(format!("{p}: parent missing (cannot evaluate)"));
                    jail_fail = true;
                    continue;
                }
                let attempt = std::fs::File::create(&probe);
                let wrote = attempt.is_ok();
                if wrote {
                    drop(attempt.unwrap());
                    let _ = std::fs::remove_file(&probe);
                }
                let expect_success = allowed;
                let ok30 = wrote == expect_success;
                if !ok30 {
                    jail_fail = true;
                }
                details.push(format!(
                    "{p}: {} (expected {})",
                    if wrote { "WRITABLE" } else { "blocked" },
                    if expect_success {
                        "writable"
                    } else {
                        "blocked"
                    }
                ));
            }
            add(
                &mut r,
                ProbeResult {
                    id: 30,
                    section: "privilege",
                    name: "fs_jail",
                    status: if jail_fail {
                        Status::FAIL
                    } else {
                        Status::PASS
                    },
                    detail: details.join("; "),
                },
            );
        }

        // 31: seccomp filter on the running process
        if cfg.sandbox.min_seccomp > 0 {
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            let seccomp = status
                .lines()
                .find(|l| l.starts_with("Seccomp:"))
                .and_then(|l| {
                    l.split_whitespace()
                        .last()
                        .and_then(|v| v.parse::<u8>().ok())
                })
                .unwrap_or(0);
            add(&mut r, ProbeResult {
                id: 31,
                section: "privilege",
                name: "seccomp_filter",
                status: if seccomp >= cfg.sandbox.min_seccomp { Status::PASS } else { Status::FAIL },
                detail: format!(
                    "Seccomp={} (need >= {}; 0=off 1=strict 2=filter; validator must run inside the confinement it verifies)",
                    seccomp, cfg.sandbox.min_seccomp
                ),
            });
        }
        // 32: effective systemd unit restrictions
        if let (Some(unit), props) = (
            &cfg.sandbox.systemd_unit,
            &cfg.sandbox.systemd_required_props,
        ) {
            if !props.is_empty() {
                let keys: Vec<&str> = props.iter().filter_map(|p| p.split('=').next()).collect();
                let cmd = format!(
                    "systemctl show {} {} --no-pager {}",
                    if cfg.sandbox.systemd_user {
                        "--user"
                    } else {
                        "--system"
                    },
                    shellq(unit),
                    keys.iter()
                        .map(|k| format!("--property={}", k))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                let (code, out) = sh(&cmd);
                let mut mismatches: Vec<String> = Vec::new();
                if code != Some(0) {
                    mismatches.push(format!(
                        "systemctl show failed exit={:?}{}",
                        code,
                        trunc(&out, 120)
                    ));
                } else {
                    for want in props {
                        let found = out.lines().any(|l| l.trim() == want.as_str());
                        if !found {
                            mismatches.push(want.clone());
                        }
                    }
                }
                add(
                    &mut r,
                    ProbeResult {
                        id: 32,
                        section: "privilege",
                        name: "systemd_unit_restrictions",
                        status: if mismatches.is_empty() {
                            Status::PASS
                        } else {
                            Status::FAIL
                        },
                        detail: if mismatches.is_empty() {
                            format!("unit {unit}: all {} required properties match", props.len())
                        } else {
                            format!("unit {unit}: missing/mismatched: {mismatches:?}")
                        },
                    },
                );
            }
        } else {
            skip(
                &mut r,
                32,
                "privilege",
                "systemd_unit_restrictions",
                "systemd_unit not configured",
            );
        }
        // 33: MAC profile attached
        if cfg.sandbox.require_mac_profile {
            let current = std::fs::read_to_string("/proc/self/attr/current").unwrap_or_default();
            let cur = current.trim().to_string();
            let confined = !cur.is_empty() && cur != "unconfined";
            add(
                &mut r,
                ProbeResult {
                    id: 33,
                    section: "privilege",
                    name: "mac_profile_attached",
                    status: if confined { Status::PASS } else { Status::FAIL },
                    detail: format!(
                        "attr/current = '{}' (need an AppArmor/SELinux profile, not unconfined)",
                        cur
                    ),
                },
            );
        }
        // 34: no_new_privs
        if cfg.sandbox.require_no_new_privs {
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            let nnp = status
                .lines()
                .find(|l| l.starts_with("NoNewPrivs:"))
                .and_then(|l| {
                    l.split_whitespace()
                        .last()
                        .and_then(|v| v.parse::<u8>().ok())
                })
                .unwrap_or(0);
            add(
                &mut r,
                ProbeResult {
                    id: 34,
                    section: "privilege",
                    name: "no_new_privs",
                    status: if nnp == 1 { Status::PASS } else { Status::FAIL },
                    detail: format!("NoNewPrivs={} (need 1; set by launcher or prctl)", nnp),
                },
            );
        }
    }

    // --- Account (35) ---
    if in_scope("account") {
        if let Some(user) = &cfg.account.expected_user {
            let uid_v = uid();
            let (_, id_out) = sh(&format!("id -un {}", uid_v));
            let cur = id_out.trim().to_string();
            add(
                &mut r,
                ProbeResult {
                    id: 35,
                    section: "account",
                    name: "expected_user",
                    status: if cur == *user {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!("running as '{}' (need '{}')", cur, user),
                },
            );
        }
        if let Some(want) = cfg.account.expected_uid {
            let ok = uid() == want;
            add(
                &mut r,
                ProbeResult {
                    id: 35,
                    section: "account",
                    name: "expected_uid",
                    status: if ok { Status::PASS } else { Status::FAIL },
                    detail: format!("uid={} (need {})", uid(), want),
                },
            );
        }
        if !cfg.account.deny_groups.is_empty() {
            let (_, groups_out) = sh("id -nG");
            let member: Vec<&str> = groups_out
                .split_whitespace()
                .filter(|g| cfg.account.deny_groups.iter().any(|d| d == g))
                .collect();
            add(
                &mut r,
                ProbeResult {
                    id: 35,
                    section: "account",
                    name: "deny_group_membership",
                    status: if member.is_empty() {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: if member.is_empty() {
                        format!("not in any of {:?}", cfg.account.deny_groups)
                    } else {
                        format!("member of privileged group(s): {member:?}")
                    },
                },
            );
        }
        if cfg.account.require_locked_password {
            let user = cfg
                .account
                .expected_user
                .clone()
                .unwrap_or_else(|| sh("id -un").1.trim().to_string());
            let (code, out) = sh(&format!("passwd -S {}", shellq(&user)));
            // passwd -S: name status L/P/NP (locked / password / none)
            let locked = out
                .split_whitespace()
                .nth(1)
                .map(|s| s == "L")
                .unwrap_or(false);
            let ok = code == Some(0) && locked;
            add(
                &mut r,
                ProbeResult {
                    id: 35,
                    section: "account",
                    name: "password_locked",
                    status: if ok { Status::PASS } else { Status::FAIL },
                    detail: format!(
                        "passwd -S {} exit={:?} status={} (need L=locked)",
                        user,
                        code,
                        out.split_whitespace().nth(1).unwrap_or("?")
                    ),
                },
            );
        }
        if !cfg.account.expected_shell.is_empty() {
            let user = cfg
                .account
                .expected_user
                .clone()
                .unwrap_or_else(|| sh("id -un").1.trim().to_string());
            let (code, out) = sh(&format!("getent passwd {}", shellq(&user)));
            let shell = out.trim().rsplit(':').next().unwrap_or("?").to_string();
            add(
                &mut r,
                ProbeResult {
                    id: 35,
                    section: "account",
                    name: "expected_shell",
                    status: if code == Some(0) && shell == cfg.account.expected_shell {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!("shell={} (need {})", shell, cfg.account.expected_shell),
                },
            );
        }
        if !cfg.account.home_modes.is_empty() {
            let home = expand("~", &ctx.home);
            let (_, out) = sh(&format!("stat -c %a {}", shellq(&home)));
            let mode = out.trim().to_string();
            add(
                &mut r,
                ProbeResult {
                    id: 35,
                    section: "account",
                    name: "home_dir_mode",
                    status: if cfg.account.home_modes.contains(&mode) {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!(
                        "home {} mode={} (allowed {:?})",
                        home, mode, cfg.account.home_modes
                    ),
                },
            );
        }
        if cfg.account.require_no_authorized_keys {
            let keys = format!("{}/.ssh/authorized_keys", ctx.home);
            let exists = std::path::Path::new(&keys).exists();
            add(
                &mut r,
                ProbeResult {
                    id: 35,
                    section: "account",
                    name: "no_authorized_keys",
                    status: if !exists { Status::PASS } else { Status::FAIL },
                    detail: format!(
                        "{} {}",
                        keys,
                        if exists {
                            "EXISTS (SSH entry path open)"
                        } else {
                            "absent"
                        }
                    ),
                },
            );
        }
    }

    // --- Secrets ---
    if in_scope("secrets") {
        let sc = &cfg.secrets;
        // 13: env secret allowlist
        let subs: Vec<String> = sc.env_substrings.iter().map(|s| s.to_lowercase()).collect();
        let allow: Vec<&str> = sc.env_allowlist.iter().map(String::as_str).collect();
        let offenders: Vec<String> = std::env::vars()
            .filter(|(k, _)| {
                let kl = k.to_lowercase();
                subs.iter().any(|s| kl.contains(s.as_str())) && !allow.contains(&k.as_str())
            })
            .map(|(k, _)| k)
            .collect();
        add(
            &mut r,
            ProbeResult {
                id: 13,
                section: "secrets",
                name: "env_allowlist",
                status: if offenders.is_empty() {
                    Status::PASS
                } else {
                    Status::FAIL
                },
                detail: if offenders.is_empty() {
                    "no secret-pattern env vars outside allowlist".into()
                } else {
                    format!("unexpected secret-pattern env vars: {offenders:?}")
                },
            },
        );
        // 14: credential paths absent
        for path in &sc.forbidden_paths {
            let p = expand(path, &ctx.home);
            let exists = std::path::Path::new(&p).exists();
            add(
                &mut r,
                ProbeResult {
                    id: 14,
                    section: "secrets",
                    name: "path_absent",
                    status: if !exists { Status::PASS } else { Status::FAIL },
                    detail: format!("{p} {}", if exists { "EXISTS" } else { "absent" }),
                },
            );
        }
        // 15: agent-scoped env file
        if let Some(f) = &sc.env_file {
            let p = expand(f, &ctx.home);
            match std::fs::read_to_string(&p) {
                Ok(content) => {
                    let lines = content.lines().count();
                    let leaky = content.to_lowercase().contains("password")
                        || content.to_lowercase().contains("private key");
                    add(&mut r, ProbeResult {
                        id: 15,
                        section: "secrets",
                        name: "env_file_agent_view",
                        status: if leaky { Status::FAIL } else { Status::PASS },
                        detail: format!("{p} readable as current user, {lines} lines; full admin-vs-agent comparison is manual"),
                    });
                }
                Err(e) => add(
                    &mut r,
                    ProbeResult {
                        id: 15,
                        section: "secrets",
                        name: "env_file_agent_view",
                        status: Status::FAIL,
                        detail: format!("{p} unreadable as current user: {e}"),
                    },
                ),
            }
        } else {
            skip(
                &mut r,
                15,
                "secrets",
                "env_file_agent_view",
                "env_file not configured",
            );
        }
        // 16: git push must fail
        if let Some(dir) = &sc.git_push_dir {
            let p = expand(dir, &ctx.home);
            let args = sc.git_push_args.join(" ");
            let (code, out) = sh(&format!("git -C {} {}", shellq(&p), args));
            add(
                &mut r,
                ProbeResult {
                    id: 16,
                    section: "secrets",
                    name: "git_push_denied",
                    status: if code != Some(0) {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!("git {args} in {p} exit={:?}{}", code, trunc(&out, 160)),
                },
            );
        } else {
            skip(
                &mut r,
                16,
                "secrets",
                "git_push_denied",
                "git_push_dir not configured",
            );
        }
    }

    // --- Resource & lifecycle ---
    if in_scope("resources") {
        let rs = &cfg.resources;
        // 17: scope with limits. systemctl show reports effective limit
        // properties; systemd-cgls prints only the cgroup tree + PIDs, which
        // can never match limit_substrings (guaranteed false FAIL).
        let unit = format!("{}.scope", rs.scope_name);
        let show_cmd = |mode: &str| {
            sh(&format!(
                "systemctl {} show {} --no-pager {}",
                mode,
                shellq(&unit),
                rs.limit_substrings
                    .iter()
                    .map(|s| format!("--property={}", s))
                    .collect::<Vec<_>>()
                    .join(" ")
            ))
        };
        let (code, out) = show_cmd("--system");
        let (code, out) = if code == Some(0) {
            (code, out)
        } else {
            show_cmd("--user")
        };
        // An unset limit reads back as "infinity" (or the u64::MAX sentinel).
        let unset = |v: &str| v.is_empty() || v == "infinity" || v == "18446744073709551615";
        let limits_present = out.lines().any(|l| {
            l.split_once('=')
                .map(|(k, v)| rs.limit_substrings.iter().any(|s| s == k) && !unset(v))
                .unwrap_or(false)
        });
        add(
            &mut r,
            ProbeResult {
                id: 17,
                section: "resources",
                name: "scope_limits",
                status: if code == Some(0) && limits_present {
                    Status::PASS
                } else {
                    Status::FAIL
                },
                detail: if code != Some(0) {
                    format!("unit {unit} not visible to systemctl (system or --user)")
                } else if limits_present {
                    format!("unit {unit} carries a non-default limit")
                } else {
                    format!(
                    "unit {unit} shows no non-default {}; if limits live on the parent slice, point scope_name/limit_substrings at the unit that carries them",
                    rs.limit_substrings.join("/")
                )
                },
            },
        );
        // 18: live CPU cap — manual cgtop observation
        skip(
            &mut r,
            18,
            "resources",
            "cpu_cap_live",
            "manual: run load inside scope, observe systemd-cgtop at quota",
        );
        // 19: disk quota
        if ctx.destructive {
            let dir = expand(&cfg.target.work_dir, &ctx.home);
            let _ = std::fs::create_dir_all(&dir);
            let (code, out) = sh(&format!(
                "fallocate -l {}G {}/arv-big && rm -f {}/arv-big",
                rs.fallocate_gib,
                shellq(&dir),
                shellq(&dir)
            ));
            add(
                &mut r,
                ProbeResult {
                    id: 19,
                    section: "resources",
                    name: "disk_quota",
                    status: if code != Some(0) {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!(
                        "fallocate {}G exit={:?}{}",
                        rs.fallocate_gib,
                        code,
                        trunc(&out, 160)
                    ),
                },
            );
        } else {
            skip(
                &mut r,
                19,
                "resources",
                "disk_quota",
                "destructive; run with --destructive",
            );
        }
        // 20: wall-clock kill
        if let Some(runner) = &rs.scope_runner_cmd {
            if ctx.destructive {
                let (code, out) = sh(&format!(
                    "timeout {}s {} bash -c 'yes > /dev/null'",
                    rs.scope_timeout_secs, runner
                ));
                add(
                    &mut r,
                    ProbeResult {
                        id: 20,
                        section: "resources",
                        name: "wall_clock_kill",
                        status: if matches!(code, Some(124) | Some(137)) {
                            Status::PASS
                        } else {
                            Status::FAIL
                        },
                        detail: format!(
                            "runner bounded (124=timeout kill, 137=SIGKILL/OOM): exit={:?}{}",
                            code,
                            trunc(&out, 160)
                        ),
                    },
                );
            } else {
                skip(
                    &mut r,
                    20,
                    "resources",
                    "wall_clock_kill",
                    "destructive; run with --destructive",
                );
            }
        } else {
            skip(
                &mut r,
                20,
                "resources",
                "wall_clock_kill",
                "scope_runner_cmd not configured",
            );
        }
    }

    // --- Audit ---
    if in_scope("audit") {
        let au = &cfg.audit;
        // 21: exec event reaches collector
        if let Some(logcmd) = &au.collector_log_cmd {
            // Embed a unique per-run marker in the executed command line so
            // the collector can only match on THIS exec, not any log noise
            // (the old last-word marker "echo" matched trivially).
            let marker = exec_marker();
            let _ = sh(&format!("{{ {}; echo {}; }}", au.exec_probe_cmd, marker));
            std::thread::sleep(std::time::Duration::from_secs(2));
            let (_, out) = sh(logcmd);
            add(
                &mut r,
                ProbeResult {
                    id: 21,
                    section: "audit",
                    name: "exec_event_collected",
                    status: if out.contains(&marker) {
                        Status::PASS
                    } else {
                        Status::FAIL
                    },
                    detail: format!(
                        "collector log {} marker '{}'",
                        if out.contains(&marker) {
                            "contains"
                        } else {
                            "MISSING"
                        },
                        marker
                    ),
                },
            );
            // 23: canary path
            match std::env::var(&au.canary_token_env) {
                Ok(token) if !token.is_empty() => {
                    // Send the token as an Authorization header (no shell, no
                    // env expansion) so the canary request is actually authenticated.
                    let ok = Command::new("curl")
                        .args([
                            "-sS",
                            "-m",
                            "5",
                            "-o",
                            "/dev/null",
                            "-w",
                            "%{http_code}",
                            "-H",
                            &format!("Authorization: Bearer {token}"),
                            &au.canary_url,
                        ])
                        .stdin(Stdio::null())
                        .output();
                    let http = ok.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    let (_, log) = sh(logcmd);
                    let token_hex = hex_prefix(&token);
                    let tripped = log.contains(&token_hex) || log.contains("canary");
                    add(
                        &mut r,
                        ProbeResult {
                            id: 23,
                            section: "audit",
                            name: "canary_trip",
                            status: if tripped { Status::PASS } else { Status::FAIL },
                            detail: format!(
                                "canary http={} collector_trip={} (token prefix {}…)",
                                http.unwrap_or_default(),
                                tripped,
                                &token_hex[..token_hex.len().min(6)]
                            ),
                        },
                    );
                }
                _ => skip(
                    &mut r,
                    23,
                    "audit",
                    "canary_trip",
                    "canary token env not set",
                ),
            }
        } else {
            skip(
                &mut r,
                21,
                "audit",
                "exec_event_collected",
                "collector_log_cmd not configured",
            );
            skip(
                &mut r,
                23,
                "audit",
                "canary_trip",
                "collector_log_cmd not configured",
            );
        }
        // 22: shipper-death alert (admin, manual/dangerous)
        skip(
            &mut r,
            22,
            "audit",
            "shipper_death_alert",
            "manual (admin): stop shipper, verify collector alert",
        );
        // 24: teardown hook
        skip(
            &mut r,
            24,
            "audit",
            "teardown_hook",
            "manual: run test session teardown, verify export commit + destroy",
        );
    }

    // --- Signing ---
    if in_scope("signing") {
        let sg = &cfg.signing;
        // 25: tamper refusal is a deliberate registry-side test
        skip(
            &mut r,
            25,
            "signing",
            "tamper_refusal",
            "manual (admin): boot test-copy with tampered artifact, verify boot refusal",
        );
        // 26: cosign verify
        if let Some(refr) = &sg.registry_ref {
            if !ctx.is_admin {
                skip(&mut r, 26, "signing", "cosign_verify", "admin required");
            } else {
                let keypart = sg
                    .cosign_key
                    .as_deref()
                    .map(|k| format!("--key {}", shellq(k)))
                    .unwrap_or_default();
                let (code, out) = sh(&format!("cosign verify {keypart} {}", shellq(refr)));
                add(
                    &mut r,
                    ProbeResult {
                        id: 26,
                        section: "signing",
                        name: "cosign_verify",
                        status: if code == Some(0) {
                            Status::PASS
                        } else {
                            Status::FAIL
                        },
                        detail: format!("cosign verify exit={:?}{}", code, trunc(&out, 200)),
                    },
                );
            }
        } else {
            skip(
                &mut r,
                26,
                "signing",
                "cosign_verify",
                "registry_ref not configured",
            );
        }
    }

    r
}

fn hex_prefix(s: &str) -> String {
    let d = sha256_hex(s.as_bytes());
    d[..16].to_string() // ASCII hex, always a char boundary
}

// ---------- CLI ----------

fn usage() -> &'static str {
    "agent-runtime-validator (arv) — harness-agnostic image validation gate

USAGE:
  arv init [PATH]                    write a starter config (default: ./config.toml)
  arv check-config [PATH]            parse + summarize config, exit 0/2
  arv validate --config PATH [--json] [--digest D] [--operator NAME]
                  [--only SECTION] [--admin] [--destructive]

Probes mirror the 26-probe verification runbook; any FAIL exits 1 and
blocks the image. SKIP is not PASS: sign-off must list every skip."
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("{}", usage());
        std::process::exit(2);
    }
    match args[1].as_str() {
        "init" => {
            let path = args.get(2).cloned().unwrap_or_else(|| "config.toml".into());
            if std::path::Path::new(&path).exists() {
                eprintln!("refusing to overwrite existing {path}");
                std::process::exit(2);
            }
            if let Err(e) = std::fs::write(&path, DEFAULT_CONFIG) {
                eprintln!("write failed: {e}");
                std::process::exit(2);
            }
            println!("wrote {path} — edit for your target, then: arv validate --config {path}");
        }
        "check-config" => {
            let path = args.get(2).cloned().unwrap_or_else(|| "config.toml".into());
            match std::fs::read_to_string(&path)
                .ok()
                .and_then(|b| toml::from_str::<Config>(&b).ok())
                .filter(|c| c.meta.config_version == 1)
            {
                Some(_) => {
                    println!("OK: {path} parses, all sections present, config_version supported")
                }
                None => {
                    eprintln!("FAIL: {path} missing or invalid");
                    std::process::exit(2);
                }
            }
        }
        "validate" => {
            let mut config_path = None;
            let mut json = false;
            let mut digest = String::new();
            let mut operator = String::new();
            let mut only = None;
            let mut admin = false;
            let mut destructive = false;
            let mut it = args[2..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--config" => config_path = it.next().cloned(),
                    "--json" => json = true,
                    "--digest" => digest = it.next().cloned().unwrap_or_default(),
                    "--operator" => operator = it.next().cloned().unwrap_or_default(),
                    "--only" => only = it.next().cloned(),
                    "--admin" => admin = true,
                    "--destructive" => destructive = true,
                    other => {
                        eprintln!("unknown arg: {other}\n{}", usage());
                        std::process::exit(2);
                    }
                }
            }
            let path = config_path.unwrap_or_else(|| "config.toml".into());
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("cannot read config {path}: {e}");
                    std::process::exit(2);
                }
            };
            let cfg: Config = match std::str::from_utf8(&bytes)
                .map_err(anyhow_str)
                .and_then(|s| toml::from_str::<Config>(s).map_err(anyhow_str))
            {
                Ok(c) => {
                    if c.meta.config_version != 1 {
                        eprintln!(
                            "unsupported config_version {} (this build supports 1)",
                            c.meta.config_version
                        );
                        std::process::exit(2);
                    }
                    c
                }
                Err(e) => {
                    eprintln!("invalid config: {e}");
                    std::process::exit(2);
                }
            };
            let is_admin = uid() == 0 && admin;
            let ctx = Ctx {
                is_admin,
                destructive,
                home: std::env::var("HOME").unwrap_or_default(),
            };
            let results = run_probes(&cfg, &ctx, only.as_deref());
            let pass = results.iter().filter(|p| p.status == Status::PASS).count();
            let fail = results.iter().filter(|p| p.status == Status::FAIL).count();
            let skipn = results.iter().filter(|p| p.status == Status::SKIP).count();

            if json {
                let hostname = hostname();
                let report = serde_json::json!({
                    "tool": "agent-runtime-validator",
                    "version": env!("CARGO_PKG_VERSION"),
                    "timestamp_utc": chrono_utc(),
                    "image_digest": digest,
                    "operator": operator,
                    "host": { "hostname": hostname, "uid": uid(), "admin_mode": is_admin },
                    "config_sha256": sha256_hex(&bytes),
                    "results": results,
                    "summary": { "pass": pass, "fail": fail, "skip": skipn },
                });
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!(
                    "agent-runtime-validator v{} — image: {} — operator: {}",
                    env!("CARGO_PKG_VERSION"),
                    if digest.is_empty() {
                        "(unset)"
                    } else {
                        &digest
                    },
                    if operator.is_empty() {
                        "(unset)"
                    } else {
                        &operator
                    }
                );
                for p in &results {
                    let tag = match p.status {
                        Status::PASS => "PASS",
                        Status::FAIL => "FAIL",
                        Status::SKIP => "SKIP",
                    };
                    println!("[{tag}] #{:<2} {:<10} {}", p.id, p.section, p.name);
                    if !p.detail.is_empty() {
                        println!("        {}", p.detail);
                    }
                }
                println!("\nsummary: {pass} PASS, {fail} FAIL, {skipn} SKIP");
                if skipn > 0 {
                    println!("NOTE: SKIP is not PASS — sign-off must account for every skip.");
                }
            }
            let code = if fail > 0 { 1 } else { 0 };
            let _ = std::io::stdout().flush();
            std::process::exit(code);
        }
        _ => {
            println!("{}", usage());
            std::process::exit(2);
        }
    }
}

fn hostname() -> String {
    sh("hostname").1.trim().to_string()
}

fn anyhow_str<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn uid() -> u32 {
    unsafe { libc::getuid() }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC3339 UTC from epoch, pure Rust (civil-from-days, Howard Hinnant's
/// algorithm) — no dependence on the host's `date` binary.
fn rfc3339_from_epoch(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn chrono_utc() -> String {
    rfc3339_from_epoch(unix_now())
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn exec_marker() -> String {
    format!("arv-exec-{}-{}", std::process::id(), unix_now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shellq_quotes_embedded_single_quotes() {
        assert_eq!(shellq("abc"), "'abc'");
        assert_eq!(shellq("it's"), "'it'\\''s'");
        assert_eq!(shellq(""), "''");
    }

    #[test]
    fn expand_handles_tilde() {
        assert_eq!(expand("~/x", "/home/a"), "/home/a/x");
        assert_eq!(expand("~", "/home/a"), "/home/a");
        assert_eq!(expand("/opt/x", "/home/a"), "/opt/x");
        // Only a leading ~/ is special; ~user is left alone.
        assert_eq!(expand("~root/x", "/home/a"), "~root/x");
    }

    #[test]
    fn trunc_never_panics_on_multibyte() {
        // Regression: &s[..n] at a non-char boundary panicked the gate.
        assert!(trunc("café detail", 4).starts_with(" :: caf"));
        assert!(trunc("日本語テスト detail", 5).starts_with(" :: "));
        assert_eq!(trunc("short", 10), " :: short");
        assert_eq!(trunc("", 10), "");
        assert!(trunc("a\nb", 10).contains(" | "));
    }

    #[test]
    fn hex_prefix_matches_sha256_of_abc() {
        // sha256("abc") = ba7816bf8f01cfea... (NIST vector)
        assert_eq!(hex_prefix("abc"), "ba7816bf8f01cfea");
        assert_eq!(sha256_hex(b"abc").len(), 64);
    }

    #[test]
    fn path_is_under_is_component_wise() {
        assert!(path_is_under("/tmp/arv-work/f", "/tmp/arv-work"));
        assert!(path_is_under("/tmp/arv-work", "/tmp/arv-work"));
        // The string-prefix trap: /tmp/arv-work-backup is NOT inside /tmp/arv-work.
        assert!(!path_is_under("/tmp/arv-work-backup/x", "/tmp/arv-work"));
        assert!(!path_is_under("/etc/passwd", "/tmp/arv-work"));
    }

    #[test]
    fn extra_url_probe_ids_stay_out_of_fixed_range() {
        assert_eq!(deny_probe_id(0), 1);
        assert_eq!(deny_probe_id(1), 3);
        assert_eq!(deny_probe_id(2), 4);
        assert_eq!(allow_probe_id(0), 2);
        // Beyond the runbook: IDs must never collide with fixed probes 5-35
        // (the old scheme mapped a 3rd extra deny URL onto DNS probe #5).
        for i in 3..8 {
            assert!(
                (40..50).contains(&deny_probe_id(i)),
                "deny id {} out of range",
                deny_probe_id(i)
            );
        }
        for i in 1..8 {
            assert!(
                allow_probe_id(i) >= 50,
                "allow id {} out of range",
                allow_probe_id(i)
            );
        }
        assert_eq!(deny_probe_id(3), 43);
        assert_eq!(allow_probe_id(1), 51);
    }

    #[test]
    fn default_config_parses() {
        let cfg: Config = toml::from_str(DEFAULT_CONFIG).expect("bundled default.toml must parse");
        assert_eq!(cfg.meta.config_version, 1);
        assert!(!cfg.secrets.env_substrings.is_empty());
        assert!(!cfg.account.deny_groups.is_empty());
    }

    #[test]
    fn exec_marker_is_shell_safe() {
        let m = exec_marker();
        assert!(m.starts_with("arv-exec-"));
        assert!(!m.contains(' ') && !m.contains('\'') && !m.contains('$'));
    }

    #[test]
    fn rfc3339_known_dates() {
        assert_eq!(rfc3339_from_epoch(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_epoch(86_400), "1970-01-02T00:00:00Z");
        assert_eq!(rfc3339_from_epoch(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_from_epoch(1_762_762_800), "2025-11-10T08:20:00Z");
        // Leap year: 2024-02-29
        assert_eq!(rfc3339_from_epoch(1_709_164_800), "2024-02-29T00:00:00Z");
    }
}
