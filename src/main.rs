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
    #[allow(dead_code)]
    meta: Meta,
    target: Target,
    egress: Egress,
    privilege: Privilege,
    #[serde(default)]
    jail: Jail,
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
    vec!["push", "origin", "main"].into_iter().map(String::from).collect()
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
    match Command::new("sh").arg("-c").arg(cmd).stdin(Stdio::null()).output() {
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
    ctx: &Ctx, // reserved for per-context gating (e.g. expected agent user)
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
            code.map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
            if expect_success { "success" } else { "fail" }
        )
        + &trunc(&out, 160),
    });
}

fn shellq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn trunc(s: &str, n: usize) -> String {
    let s = s.trim().replace('\n', " | ");
    if s.len() > n {
        format!(" :: {}…", &s[..n])
    } else if !s.is_empty() {
        format!(" :: {s}")
    } else {
        String::new()
    }
}

fn skip(results: &mut Vec<ProbeResult>, id: u32, section: &'static str, name: &'static str, why: &str) {
    results.push(ProbeResult { id, section, name, status: Status::SKIP, detail: why.into() });
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
        // Runbook numbering: #1 = first deny, #2 = allow, #3.. = remaining denies.
        let mut deny_i = 0u32;
        for url in &eg.deny_urls {
            let id = if deny_i == 0 { 1 } else { 2 + deny_i };
            net_probe(&mut r, ctx, eg, url, false, id);
            deny_i += 1;
        }
        // runbook numbers 3,4 are deny probes; keep ids as configured order
        if eg.allow_enabled {
            for url in &eg.allow_urls {
                net_probe(&mut r, ctx, eg, url, true, 2);
            }
        } else {
            skip(&mut r, 2, "egress", "allow", "allow_enabled=false for this task class");
        }
        // Probe 5: direct DNS to external resolver must fail
        if let Some(server) = &eg.dns_direct_server {
            let (code, out) = sh(&format!("dig +time=3 +tries=1 @{} evil.example", shellq(server)));
            add(&mut r, ProbeResult {
                id: 5,
                section: "egress",
                name: "dns_direct_deny",
                status: if code != Some(0) { Status::PASS } else { Status::FAIL },
                detail: format!("dig @{server} exit={:?}{}", code, trunc(&out, 120)),
            });
        } else {
            skip(&mut r, 5, "egress", "dns_direct_deny", "dns_direct_server not configured");
        }
        // Probe 6: resolution via local resolver must succeed
        if let Some(name) = &eg.dns_resolver_name {
            let (code, out) = sh(&format!("dig +time=3 +tries=1 {}", shellq(name)));
            let ok = code == Some(0) && out.contains("status: NOERROR") && out.contains("ANSWER: 1");
            add(&mut r, ProbeResult {
                id: 6,
                section: "egress",
                name: "dns_via_resolver",
                status: if ok { Status::PASS } else { Status::FAIL },
                detail: format!("dig {name} exit={:?}{}", code, trunc(&out, 120)),
            });
        } else {
            skip(&mut r, 6, "egress", "dns_via_resolver", "dns_resolver_name not configured");
        }
        // Probe 7: non-allowlisted name must NXDOMAIN/REFUSED
        if let Some(name) = &eg.dns_nxdomain_name {
            let (code, out) = sh(&format!("dig +time=3 +tries=1 {}", shellq(name)));
            let refused = out.contains("status: NXDOMAIN") || out.contains("status: REFUSED");
            let ok = refused || code != Some(0);
            add(&mut r, ProbeResult {
                id: 7,
                section: "egress",
                name: "dns_nxdomain",
                status: if ok { Status::PASS } else { Status::FAIL },
                detail: format!("dig {name} exit={:?}{}", code, trunc(&out, 120)),
            });
        } else {
            skip(&mut r, 7, "egress", "dns_nxdomain", "dns_nxdomain_name not configured");
        }
    }

    // --- Privilege ---
    if in_scope("privilege") {
        let pv = &cfg.privilege;
        // 8: no passwordless sudo
        if !pv.sudo_expected {
            let (code, out) = sh("sudo -n true");
            add(&mut r, ProbeResult {
                id: 8,
                section: "privilege",
                name: "no_sudo",
                status: if code != Some(0) { Status::PASS } else { Status::FAIL },
                detail: format!("sudo -n true exit={:?}{}", code, trunc(&out, 120)),
            });
        }
        // 9: nft ruleset unreadable
        if pv.nft_check {
            let (code, out) = sh("nft list ruleset");
            add(&mut r, ProbeResult {
                id: 9,
                section: "privilege",
                name: "nft_denied",
                status: if code != Some(0) { Status::PASS } else { Status::FAIL },
                detail: format!("nft list ruleset exit={:?}{}", code, trunc(&out, 120)),
            });
        }
        // 10: no CAP_NET_ADMIN
        if let Some(via) = &pv.route_test_via {
            let (code, out) = sh(&format!("ip route add 10.9.9.9/32 via {}", shellq(via)));
            add(&mut r, ProbeResult {
                id: 10,
                section: "privilege",
                name: "no_net_admin",
                status: if code != Some(0) { Status::PASS } else { Status::FAIL },
                detail: format!("ip route add exit={:?}{}", code, trunc(&out, 120)),
            });
        } else {
            skip(&mut r, 10, "privilege", "no_net_admin", "route_test_via not configured");
        }
        // 11: harness tree immutable
        for path in &pv.remount_paths {
            let p = expand(path, &ctx.home);
            let (code, out) = sh(&format!("mount -o remount,rw {}", shellq(&p)));
            add(&mut r, ProbeResult {
                id: 11,
                section: "privilege",
                name: "remount_denied",
                status: if code != Some(0) { Status::PASS } else { Status::FAIL },
                detail: format!("remount,rw {p} exit={:?}{}", code, trunc(&out, 120)),
            });
        }
        // 12: exact suid set
        let (code, out) = sh("find / -xdev -perm -4000 -user root 2>/dev/null");
        let found: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        let allow: Vec<&str> = pv.suid_allowlist.iter().map(String::as_str).collect();
        let mut extra: Vec<&str> = found.iter().copied().filter(|b| !allow.contains(b)).collect();
        let missing: Vec<&str> = allow.iter().copied().filter(|b| !found.contains(b)).collect();
        extra.sort_unstable();
        let ok = code.is_some() && extra.is_empty() && missing.is_empty();
        add(&mut r, ProbeResult {
            id: 12,
            section: "privilege",
            name: "suid_exact_set",
            status: if ok { Status::PASS } else { Status::FAIL },
            detail: format!(
                "found={} extra={:?} missing_from_image={:?}{}",
                found.len(), extra, missing, trunc(&out, 200)
            ),
        });
        // 27: non-root user with no effective capabilities
        if pv.require_non_root {
            let uid_v = uid();
            let caps = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines().find(|l| l.starts_with("CapEff:")).map(|l| {
                        l.split_whitespace().last().unwrap_or("?").to_string()
                    })
                })
                .unwrap_or_else(|| "?".into());
            let no_caps = caps == "0000000000000000";
            let ok27 = uid_v != 0 && no_caps;
            add(&mut r, ProbeResult {
                id: 27,
                section: "privilege",
                name: "non_root_no_caps",
                status: if ok27 { Status::PASS } else { Status::FAIL },
                detail: format!("uid={} CapEff={} (need uid!=0 and zero effective caps)", uid_v, caps),
            });
        }
        // 28: bubblewrap constructs a real sandbox
        if pv.check_bwrap {
            let (code, out) = sh("bwrap --ro-bind / / --proc /proc --dev /dev --unshare-all true");
            let bwrap_ok = code == Some(0);
            // userns availability explains most bwrap failures
            let userns_exit = sh("unshare --user --map-root-user true").0;
            add(&mut r, ProbeResult {
                id: 28,
                section: "privilege",
                name: "bwrap_sandbox",
                status: if bwrap_ok { Status::PASS } else { Status::FAIL },
                detail: format!(
                    "bwrap exit={:?} userns_exit={:?}{}",
                    code,
                    userns_exit,
                    if bwrap_ok { String::new() } else { trunc(&out, 160) }
                ),
            });
        }
        // 29: Landlock active in kernel LSM list
        if pv.check_landlock {
            let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
            let has = lsm.split(',').any(|s| s.trim() == "landlock");
            add(&mut r, ProbeResult {
                id: 29,
                section: "privilege",
                name: "landlock_kernel",
                status: if has { Status::PASS } else { Status::FAIL },
                detail: if lsm.is_empty() {
                    "/sys/kernel/security/lsm unreadable (securityfs not mounted?)".into()
                } else {
                    format!("lsm list: {}", lsm.trim())
                },
            });
        }
        // 30: filesystem jail — writes outside allowed roots fail, inside succeed
        if !cfg.jail.deny_write_paths.is_empty() || !cfg.jail.allow_write_paths.is_empty() {
            let mut jail_fail = false;
            let mut details: Vec<String> = Vec::new();
            for path in cfg.jail.deny_write_paths.iter().chain(cfg.jail.allow_write_paths.iter()) {
                let p = expand(path, &ctx.home);
                let allowed = cfg.jail.allow_write_paths.iter().any(|a| path.starts_with(a.as_str()) || expand(a, &ctx.home) == p);
                if allowed {
                    let _ = std::fs::create_dir_all(&p);
                }
                let probe = format!("{}/arv-probe-{}", p, std::process::id());
                if !std::path::Path::new(&p).is_dir() {
                    details.push(format!("{p}: parent missing (not evaluated)"));
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
                    if expect_success { "writable" } else { "blocked" }
                ));
            }
            add(&mut r, ProbeResult {
                id: 30,
                section: "privilege",
                name: "fs_jail",
                status: if jail_fail { Status::FAIL } else { Status::PASS },
                detail: details.join("; "),
            });
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
        add(&mut r, ProbeResult {
            id: 13,
            section: "secrets",
            name: "env_allowlist",
            status: if offenders.is_empty() { Status::PASS } else { Status::FAIL },
            detail: if offenders.is_empty() {
                "no secret-pattern env vars outside allowlist".into()
            } else {
                format!("unexpected secret-pattern env vars: {offenders:?}")
            },
        });
        // 14: credential paths absent
        for path in &sc.forbidden_paths {
            let p = expand(path, &ctx.home);
            let exists = std::path::Path::new(&p).exists();
            add(&mut r, ProbeResult {
                id: 14,
                section: "secrets",
                name: "path_absent",
                status: if !exists { Status::PASS } else { Status::FAIL },
                detail: format!("{p} {}", if exists { "EXISTS" } else { "absent" }),
            });
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
                Err(e) => add(&mut r, ProbeResult {
                    id: 15,
                    section: "secrets",
                    name: "env_file_agent_view",
                    status: Status::FAIL,
                    detail: format!("{p} unreadable as current user: {e}"),
                }),
            }
        } else {
            skip(&mut r, 15, "secrets", "env_file_agent_view", "env_file not configured");
        }
        // 16: git push must fail
        if let Some(dir) = &sc.git_push_dir {
            let p = expand(dir, &ctx.home);
            let args = sc.git_push_args.join(" ");
            let (code, out) = sh(&format!("git -C {} {}", shellq(&p), args));
            add(&mut r, ProbeResult {
                id: 16,
                section: "secrets",
                name: "git_push_denied",
                status: if code != Some(0) { Status::PASS } else { Status::FAIL },
                detail: format!("git {args} in {p} exit={:?}{}", code, trunc(&out, 160)),
            });
        } else {
            skip(&mut r, 16, "secrets", "git_push_denied", "git_push_dir not configured");
        }
    }

    // --- Resource & lifecycle ---
    if in_scope("resources") {
        let rs = &cfg.resources;
        // 17: scope with limits
        let (code, out) = sh("systemd-cgls --no-pager 2>/dev/null || true");
        let scope_line = out.lines().find(|l| l.contains(&rs.scope_name));
        let limits_present = scope_line
            .map(|l| rs.limit_substrings.iter().any(|s| l.contains(s)))
            .unwrap_or(false);
        add(&mut r, ProbeResult {
            id: 17,
            section: "resources",
            name: "scope_limits",
            status: if code == Some(0) && scope_line.is_some() && limits_present {
                Status::PASS
            } else {
                Status::FAIL
            },
            detail: match scope_line {
                Some(l) => format!("scope line: {}", trunc(l, 160)),
                None => format!("no cgroup line containing '{}'", rs.scope_name),
            },
        });
        // 18: live CPU cap — manual cgtop observation
        skip(&mut r, 18, "resources", "cpu_cap_live", "manual: run load inside scope, observe systemd-cgtop at quota");
        // 19: disk quota
        if ctx.destructive {
            let dir = expand(&cfg.target.work_dir, &ctx.home);
            let _ = std::fs::create_dir_all(&dir);
            let (code, out) = sh(&format!(
                "fallocate -l {}G {}/arv-big && rm -f {}/arv-big",
                rs.fallocate_gib, shellq(&dir), shellq(&dir)
            ));
            add(&mut r, ProbeResult {
                id: 19,
                section: "resources",
                name: "disk_quota",
                status: if code != Some(0) { Status::PASS } else { Status::FAIL },
                detail: format!("fallocate {}G exit={:?}{}", rs.fallocate_gib, code, trunc(&out, 160)),
            });
        } else {
            skip(&mut r, 19, "resources", "disk_quota", "destructive; run with --destructive");
        }
        // 20: wall-clock kill
        if let Some(runner) = &rs.scope_runner_cmd {
            if ctx.destructive {
                let (code, out) = sh(&format!(
                    "timeout {}s {} bash -c 'yes > /dev/null'",
                    rs.scope_timeout_secs, runner
                ));
                add(&mut r, ProbeResult {
                    id: 20,
                    section: "resources",
                    name: "wall_clock_kill",
                    status: if code == Some(124) { Status::PASS } else { Status::FAIL },
                    detail: format!("runner killed by timeout: exit={:?}{}", code, trunc(&out, 160)),
                });
            } else {
                skip(&mut r, 20, "resources", "wall_clock_kill", "destructive; run with --destructive");
            }
        } else {
            skip(&mut r, 20, "resources", "wall_clock_kill", "scope_runner_cmd not configured");
        }
    }

    // --- Audit ---
    if in_scope("audit") {
        let au = &cfg.audit;
        // 21: exec event reaches collector
        if let Some(logcmd) = &au.collector_log_cmd {
            let _ = sh(&au.exec_probe_cmd);
            std::thread::sleep(std::time::Duration::from_secs(2));
            let (_, out) = sh(logcmd);
            let marker = au.exec_probe_cmd.split_whitespace().last().unwrap_or("").trim_matches('\'');
            add(&mut r, ProbeResult {
                id: 21,
                section: "audit",
                name: "exec_event_collected",
                status: if out.contains(marker) { Status::PASS } else { Status::FAIL },
                detail: format!("collector log {} marker '{}'", if out.contains(marker) { "contains" } else { "MISSING" }, marker),
            });
            // 23: canary path
            match std::env::var(&au.canary_token_env) {
                Ok(token) if !token.is_empty() => {
                    let ok = Command::new("curl")
                        .args(["-sS", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", &au.canary_url])
                        .env("ARV_BEARER", &token)
                        .stdin(Stdio::null())
                        .output();
                    let http = ok.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    let (_, log) = sh(logcmd);
                    let token_hex = hex_prefix(&token);
                    let tripped = log.contains(&token_hex) || log.contains("canary");
                    add(&mut r, ProbeResult {
                        id: 23,
                        section: "audit",
                        name: "canary_trip",
                        status: if tripped { Status::PASS } else { Status::FAIL },
                        detail: format!("canary http={} collector_trip={} (token prefix {}…)", http.unwrap_or_default(), tripped, &token_hex[..token_hex.len().min(6)]),
                    });
                }
                _ => skip(&mut r, 23, "audit", "canary_trip", "canary token env not set"),
            }
        } else {
            skip(&mut r, 21, "audit", "exec_event_collected", "collector_log_cmd not configured");
            skip(&mut r, 23, "audit", "canary_trip", "collector_log_cmd not configured");
        }
        // 22: shipper-death alert (admin, manual/dangerous)
        skip(&mut r, 22, "audit", "shipper_death_alert", "manual (admin): stop shipper, verify collector alert");
        // 24: teardown hook
        skip(&mut r, 24, "audit", "teardown_hook", "manual: run test session teardown, verify export commit + destroy");
    }

    // --- Signing ---
    if in_scope("signing") {
        let sg = &cfg.signing;
        // 25: tamper refusal is a deliberate registry-side test
        skip(&mut r, 25, "signing", "tamper_refusal", "manual (admin): boot test-copy with tampered artifact, verify boot refusal");
        // 26: cosign verify
        if let Some(refr) = &sg.registry_ref {
            if !ctx.is_admin {
                skip(&mut r, 26, "signing", "cosign_verify", "admin required");
            } else {
                let keypart = sg.cosign_key.as_deref().map(|k| format!("--key {}", shellq(k))).unwrap_or_default();
                let (code, out) = sh(&format!("cosign verify {keypart} {}", shellq(refr)));
                add(&mut r, ProbeResult {
                    id: 26,
                    section: "signing",
                    name: "cosign_verify",
                    status: if code == Some(0) { Status::PASS } else { Status::FAIL },
                    detail: format!("cosign verify exit={:?}{}", code, trunc(&out, 200)),
                });
            }
        } else {
            skip(&mut r, 26, "signing", "cosign_verify", "registry_ref not configured");
        }
    }

    r
}

fn hex_prefix(s: &str) -> String {
    let d: String = Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    d[..16].to_string()
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
            match std::fs::read_to_string(&path).ok().and_then(|b| toml::from_str::<Config>(&b).ok()) {
                Some(_) => println!("OK: {path} parses and all sections present"),
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
            let cfg: Config = match std::str::from_utf8(&bytes).map_err(anyhow_str)
                .and_then(|s| toml::from_str::<Config>(s).map_err(anyhow_str))
            {
                Ok(c) => c,
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
                    "config_sha256": hex_prefix(&format!("{}:{}", path, Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>())),
                    "results": results,
                    "summary": { "pass": pass, "fail": fail, "skip": skipn },
                });
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!("agent-runtime-validator v{} — image: {} — operator: {}", env!("CARGO_PKG_VERSION"),
                    if digest.is_empty() { "(unset)" } else { &digest },
                    if operator.is_empty() { "(unset)" } else { &operator });
                for p in &results {
                    let tag = match p.status { Status::PASS => "PASS", Status::FAIL => "FAIL", Status::SKIP => "SKIP" };
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

fn chrono_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // RFC3339 without external crates: delegate to date when available
    let (_, out) = sh(&format!("date -u -d @{secs} +%Y-%m-%dT%H:%M:%SZ 2>/dev/null"));
    if out.trim().is_empty() {
        format!("{secs}")
    } else {
        out.trim().to_string()
    }
}
