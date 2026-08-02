use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use globset::{Glob, GlobSetBuilder};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Parser, Debug)]
#[command(
    name = "sealhook",
    disable_help_flag = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[arg(long, global = true, default_value = ".sealhook.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Encrypt(CommandOpts),
    Decrypt(CommandOpts),
    Status,
    #[command(name = "check-staged")]
    CheckStaged,
}

#[derive(Parser, Debug)]
struct CommandOpts {
    #[arg(long)]
    force: bool,
    #[arg(long)]
    stage: bool,
}

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    sealhook: Option<SealhookSection>,
    age: Option<AgeSection>,
    #[serde(default)]
    secrets: Vec<SecretSection>,
}

#[derive(Debug, Deserialize, Default)]
struct SealhookSection {
    engine: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct AgeSection {
    recipients_file: Option<String>,
    identity_files: Option<Vec<String>>,
    armor: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SecretSection {
    path: Option<String>,
    pattern: Option<String>,
    encrypted: Option<String>,
    mode: Option<String>,
}

#[derive(Debug, Clone)]
struct Config {
    base: PathBuf,
    engine: String,
    age: AgeConfig,
    secrets: Vec<Secret>,
}

#[derive(Debug, Clone)]
struct AgeConfig {
    recipients_file: String,
    identity_files: Vec<String>,
    armor: bool,
}

#[derive(Debug, Clone)]
struct Secret {
    path: String,
    encrypted: String,
    mode: u32,
}

fn main() {
    let exit_code = match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            1
        }
    };
    std::process::exit(exit_code);
}

fn run() -> Result<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || matches!(args.get(1).map(String::as_str), Some("--help" | "-h")) {
        print_usage(&mut io::stdout())?;
        return Ok(0);
    }

    let cli = Cli::try_parse().map_err(|err| anyhow!(err.to_string()))?;
    let cfg = load_config(&cli.config)?;
    match cli.command {
        Some(Commands::Encrypt(opts)) => encrypt(&cfg, opts.force, opts.stage),
        Some(Commands::Decrypt(opts)) => decrypt(&cfg, opts.force),
        Some(Commands::Status) => status(&cfg),
        Some(Commands::CheckStaged) => check_staged(&cfg),
        None => {
            print_usage(&mut io::stdout())?;
            Ok(0)
        }
    }
}

fn print_usage(mut out: impl Write) -> Result<()> {
    writeln!(
        out,
        "usage: sealhook [--config .sealhook.toml] <command>\n\ncommands:\n  encrypt [--stage] [--force]   encrypt changed plaintext secrets to .age files\n  decrypt [--force]             decrypt changed .age files to plaintext secrets\n  status                        show plaintext/encrypted sync state\n  check-staged                  fail if plaintext secret files are staged"
    )?;
    Ok(())
}

fn load_config(path: &Path) -> Result<Config> {
    let path = absolutize(path)?;
    let base = path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("config path has no parent: {}", path.display()))?;
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let parsed: FileConfig =
        toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;

    let engine = parsed
        .sealhook
        .and_then(|s| s.engine)
        .unwrap_or_else(|| "age".to_string());
    if engine != "age" {
        bail!("unsupported sealhook engine: {engine}");
    }

    let age = parsed.age.unwrap_or_default();
    let age = AgeConfig {
        recipients_file: age
            .recipients_file
            .unwrap_or_else(|| ".age-recipients".to_string()),
        identity_files: age.identity_files.unwrap_or_else(|| {
            vec![
                "~/.config/age/keys.txt".to_string(),
                "~/.config/age/se.key".to_string(),
            ]
        }),
        armor: age.armor.unwrap_or(false),
    };

    let mut secrets = BTreeMap::new();
    let has_secret_entries = !parsed.secrets.is_empty();
    for secret in parsed.secrets {
        for expanded in expand_secret_section(secret, &base)? {
            secrets.insert(expanded.path.clone(), expanded);
        }
    }
    if !has_secret_entries {
        bail!("no [[secrets]] entries configured");
    }
    let secrets = secrets.into_values().collect();

    Ok(Config {
        base,
        engine,
        age,
        secrets,
    })
}

fn expand_secret_section(secret: SecretSection, base: &Path) -> Result<Vec<Secret>> {
    let mode = parse_mode(
        secret.mode.as_deref(),
        secret.path.as_deref().or(secret.pattern.as_deref()),
    )?;
    match (secret.path, secret.pattern) {
        (Some(path), None) => {
            let encrypted = secret.encrypted.unwrap_or_else(|| format!("{path}.age"));
            Ok(vec![Secret {
                path,
                encrypted,
                mode,
            }])
        }
        (None, Some(pattern)) => {
            if secret.encrypted.is_some() {
                bail!("[[secrets]] entries with pattern cannot set encrypted; encrypted path defaults to <path>.age");
            }
            expand_secret_pattern(&pattern, base, mode)
        }
        (Some(_), Some(_)) => {
            bail!("[[secrets]] entries must set either path or pattern, not both")
        }
        (None, None) => bail!("[[secrets]] entries must set path or pattern"),
    }
}

fn parse_mode(mode: Option<&str>, label: Option<&str>) -> Result<u32> {
    match mode {
        Some(m) => u32::from_str_radix(m.trim_start_matches("0o"), 8)
            .with_context(|| format!("invalid mode for {}", label.unwrap_or("secret"))),
        None => Ok(0o600),
    }
}

fn expand_secret_pattern(pattern: &str, base: &Path, mode: u32) -> Result<Vec<Secret>> {
    let mut builder = GlobSetBuilder::new();
    builder.add(Glob::new(pattern).with_context(|| format!("invalid secret pattern: {pattern}"))?);
    let matcher = builder.build()?;

    let mut secrets = BTreeMap::new();
    for file in collect_files(base)? {
        let rel = relative_slash_path(&file, base)?;
        if matcher.is_match(&rel) {
            secrets.insert(
                rel.clone(),
                Secret {
                    path: rel.clone(),
                    encrypted: format!("{rel}.age"),
                    mode,
                },
            );
        }
        if let Some(plain) = rel.strip_suffix(".age") {
            if matcher.is_match(plain) {
                secrets.insert(
                    plain.to_string(),
                    Secret {
                        path: plain.to_string(),
                        encrypted: rel,
                        mode,
                    },
                );
            }
        }
    }
    Ok(secrets.into_values().collect())
}

fn collect_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_into(dir, &mut files)?;
    Ok(files)
}

fn collect_files_into(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read directory {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if entry.file_name() == ".git" {
                continue;
            }
            collect_files_into(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn relative_slash_path(path: &Path, base: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(base)
        .with_context(|| format!("make {} relative to {}", path.display(), base.display()))?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

fn encrypt(cfg: &Config, force: bool, stage: bool) -> Result<i32> {
    ensure_age_engine(cfg)?;
    let mut changed = Vec::new();
    for secret in &cfg.secrets {
        let plain = resolve_path(&secret.path, &cfg.base);
        let encrypted = resolve_path(&secret.encrypted, &cfg.base);
        if !plain.exists() {
            eprintln!("skip encrypt: plaintext missing: {}", secret.path);
            continue;
        }
        if encrypted.exists() && !force && !newer(&plain, &encrypted) {
            println!("ok encrypt: {} is up to date", secret.encrypted);
            continue;
        }
        fs::create_dir_all(parent_dir(&encrypted)?)?;
        let tmp = temp_path_next_to(&encrypted);
        let _ = fs::remove_file(&tmp);
        println!("encrypt: {} -> {}", secret.path, secret.encrypted);
        age_encrypt_file(cfg, &plain, &tmp)
            .with_context(|| format!("age encrypt {}", secret.path))?;
        fs::rename(&tmp, &encrypted)?;
        copy_mtime(&plain, &encrypted);
        changed.push(encrypted);
    }

    if stage && !changed.is_empty() {
        let status = Command::new("git")
            .arg("add")
            .args(&changed)
            .status()
            .context("run git add")?;
        if !status.success() {
            bail!("git add failed with status {status}");
        }
    }
    Ok(0)
}

fn decrypt(cfg: &Config, force: bool) -> Result<i32> {
    ensure_age_engine(cfg)?;
    if find_identity(&cfg.age, &cfg.base).is_none() {
        return Err(anyhow!(
            "no age identity file found; set AGE_IDENTITY_FILE or create configured key file"
        ));
    }

    let mut rc = 0;
    for secret in &cfg.secrets {
        let plain = resolve_path(&secret.path, &cfg.base);
        let encrypted = resolve_path(&secret.encrypted, &cfg.base);
        if !encrypted.exists() {
            eprintln!("skip decrypt: encrypted file missing: {}", secret.encrypted);
            continue;
        }
        if plain.exists() && !force && newer(&plain, &encrypted) {
            eprintln!(
                "conflict decrypt: plaintext is newer than encrypted file; not overwriting: {}",
                secret.path
            );
            rc = 2;
            continue;
        }
        if plain.exists() && !force && !newer(&encrypted, &plain) {
            println!("ok decrypt: {} is up to date", secret.path);
            continue;
        }
        fs::create_dir_all(parent_dir(&plain)?)?;
        let tmp = temp_path_next_to(&plain);
        let _ = fs::remove_file(&tmp);
        println!("decrypt: {} -> {}", secret.encrypted, secret.path);
        age_decrypt_file(cfg, &encrypted, &tmp)
            .with_context(|| format!("age decrypt {}", secret.encrypted))?;
        fs::rename(&tmp, &plain)?;
        set_mode(&plain, secret.mode)?;
        copy_mtime(&encrypted, &plain);
    }
    Ok(rc)
}

fn status(cfg: &Config) -> Result<i32> {
    let mut rc = 0;
    for secret in &cfg.secrets {
        let plain = resolve_path(&secret.path, &cfg.base);
        let encrypted = resolve_path(&secret.encrypted, &cfg.base);
        match (plain.exists(), encrypted.exists()) {
            (false, false) => {
                println!("missing both: {} / {}", secret.path, secret.encrypted);
                rc = 1;
            }
            (true, false) => {
                println!("needs encrypt: {} -> {}", secret.path, secret.encrypted);
                rc = 1;
            }
            (false, true) => {
                println!("needs decrypt: {} -> {}", secret.encrypted, secret.path);
                rc = 1;
            }
            (true, true) if newer(&plain, &encrypted) => {
                println!("plaintext newer: {} -> {}", secret.path, secret.encrypted);
                rc = 1;
            }
            (true, true) if newer(&encrypted, &plain) => {
                println!("encrypted newer: {} -> {}", secret.encrypted, secret.path);
                rc = 1;
            }
            (true, true) => println!("in sync: {} / {}", secret.path, secret.encrypted),
        }
    }
    Ok(rc)
}

fn check_staged(cfg: &Config) -> Result<i32> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .output()
        .context("run git diff --cached")?;
    if !output.status.success() {
        bail!("git diff --cached failed");
    }
    let staged: HashSet<PathBuf> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| resolve_path(line.trim(), &cfg.base))
        .collect();

    let bad: Vec<_> = cfg
        .secrets
        .iter()
        .filter(|secret| staged.contains(&resolve_path(&secret.path, &cfg.base)))
        .collect();
    if bad.is_empty() {
        return Ok(0);
    }

    eprintln!("ERROR: plaintext secret file(s) are staged. Commit encrypted .age files only:");
    for secret in bad {
        eprintln!("  - {}", secret.path);
    }
    Ok(1)
}

fn ensure_age_engine(cfg: &Config) -> Result<()> {
    if cfg.engine == "age" {
        Ok(())
    } else {
        bail!("unsupported sealhook engine: {}", cfg.engine)
    }
}

fn age_encrypt_file(cfg: &Config, input: &Path, output: &Path) -> Result<()> {
    let mut cmd = Command::new("age");
    if cfg.age.armor {
        cmd.arg("--armor");
    }
    cmd.arg("--recipients-file")
        .arg(resolve_path(&cfg.age.recipients_file, &cfg.base))
        .arg("--output")
        .arg(output)
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    run_external(cmd, "age encrypt")
}

fn age_decrypt_file(cfg: &Config, input: &Path, output: &Path) -> Result<()> {
    let identity = find_identity(&cfg.age, &cfg.base).ok_or_else(|| {
        anyhow!("no age identity file found; set AGE_IDENTITY_FILE or create configured key file")
    })?;
    let mut cmd = Command::new("age");
    cmd.arg("--decrypt")
        .arg("--identity")
        .arg(identity)
        .arg("--output")
        .arg(output)
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    run_external(cmd, "age decrypt")
}

fn run_external(mut cmd: Command, label: &str) -> Result<()> {
    let output = cmd.output().with_context(|| format!("spawn {label}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        bail!("{label} failed with status {}", output.status)
    } else {
        bail!("{label} failed with status {}: {stderr}", output.status)
    }
}

fn find_identity(age: &AgeConfig, base: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("AGE_IDENTITY_FILE") {
        if !path.is_empty() {
            candidates.push(path);
        }
    }
    candidates.extend(age.identity_files.clone());
    candidates
        .into_iter()
        .map(|path| resolve_path(path, base))
        .find(|path| path.exists())
}

fn resolve_path(path: impl AsRef<str>, base: &Path) -> PathBuf {
    let mut path = path.as_ref().to_string();
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            path = PathBuf::from(home)
                .join(rest)
                .to_string_lossy()
                .into_owned();
        }
    }
    let expanded = expand_env_vars(&path);
    let pb = PathBuf::from(expanded);
    if pb.is_absolute() {
        pb
    } else {
        base.join(pb)
    }
}

fn expand_env_vars(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' {
            let mut name = String::new();
            while let Some(&next) = chars.peek() {
                if next == '_' || next.is_ascii_alphanumeric() {
                    name.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            if name.is_empty() {
                out.push('$');
            } else if let Ok(value) = std::env::var(&name) {
                out.push_str(&value);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn newer(a: &Path, b: &Path) -> bool {
    let Ok(a_meta) = fs::metadata(a) else {
        return false;
    };
    let Ok(b_meta) = fs::metadata(b) else {
        return false;
    };
    match (a_meta.modified(), b_meta.modified()) {
        (Ok(a_time), Ok(b_time)) => a_time > b_time,
        _ => false,
    }
}

fn copy_mtime(source: &Path, target: &Path) {
    let Ok(meta) = fs::metadata(source) else {
        return;
    };
    let Ok(modified) = meta.modified() else {
        return;
    };
    let atime = filetime::FileTime::from_system_time(modified);
    let mtime = filetime::FileTime::from_system_time(modified);
    let _ = filetime::set_file_times(target, atime, mtime);
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn parent_dir(path: &Path) -> Result<&Path> {
    path.parent()
        .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))
}

fn temp_path_next_to(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("sealhook.tmp");
    let pid = std::process::id();
    parent_dir(path)
        .unwrap_or_else(|_| Path::new("."))
        .join(format!(".{name}.{pid}.tmp"))
}

fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
