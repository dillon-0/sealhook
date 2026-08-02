use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn write_minimal_config(dir: &std::path::Path) {
    fs::write(
        dir.join(".sealhook.toml"),
        r#"[sealhook]
engine = "age"

[[secrets]]
path = ".env"
"#,
    )
    .unwrap();
}

#[test]
fn prints_help_with_expected_commands() {
    let mut cmd = Command::cargo_bin("sealhook").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "sealhook [--config .sealhook.toml] <command>",
        ))
        .stdout(predicate::str::contains("encrypt"))
        .stdout(predicate::str::contains("check-staged"));
}

#[test]
fn accepts_global_config_before_command() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("custom.toml");
    fs::write(
        &config_path,
        r#"[sealhook]
engine = "age"

[[secrets]]
path = "secret.txt"
"#,
    )
    .unwrap();
    fs::write(dir.path().join("secret.txt"), "TOKEN=example\n").unwrap();

    let mut cmd = Command::cargo_bin("sealhook").unwrap();
    cmd.current_dir(dir.path())
        .arg("--config")
        .arg(&config_path)
        .arg("status")
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "needs encrypt: secret.txt -> secret.txt.age",
        ));
}

#[test]
fn status_reports_default_encrypted_path() {
    let dir = tempdir().unwrap();
    write_minimal_config(dir.path());
    fs::write(dir.path().join(".env"), "TOKEN=example").unwrap();

    let mut cmd = Command::cargo_bin("sealhook").unwrap();
    cmd.current_dir(dir.path())
        .arg("status")
        .assert()
        .failure()
        .stdout(predicate::str::contains("needs encrypt: .env -> .env.age"));
}

#[test]
fn status_expands_secret_patterns_for_plaintext_and_encrypted_files() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join(".sealhook.toml"),
        r#"[sealhook]
engine = "age"

[[secrets]]
pattern = "config/**/*.env"
"#,
    )
    .unwrap();
    fs::create_dir_all(dir.path().join("config/service-a")).unwrap();
    fs::create_dir_all(dir.path().join("config/service-b")).unwrap();
    fs::write(dir.path().join("config/service-a/.env"), "TOKEN=a").unwrap();
    fs::write(
        dir.path().join("config/service-b/.env.age"),
        "AGE-ENCRYPTED",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("sealhook").unwrap();
    cmd.current_dir(dir.path())
        .arg("status")
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "needs encrypt: config/service-a/.env -> config/service-a/.env.age",
        ))
        .stdout(predicate::str::contains(
            "needs decrypt: config/service-b/.env.age -> config/service-b/.env",
        ));
}

#[test]
fn decrypt_fails_when_no_age_identity_found() {
    let dir = tempdir().unwrap();
    write_minimal_config(dir.path());
    fs::write(dir.path().join(".env.age"), "AGE-ENCRYPTED").unwrap();

    let mut cmd = Command::cargo_bin("sealhook").unwrap();
    cmd.current_dir(dir.path())
        .env("HOME", dir.path().join("empty-home"))
        .arg("decrypt")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no age identity file found"));
}

#[test]
fn encrypt_and_decrypt_round_trip_through_system_age_cli() {
    let dir = tempdir().unwrap();
    write_minimal_config(dir.path());

    let keys = Command::new("age-keygen")
        .output()
        .expect("age-keygen exists");
    assert!(keys.status.success());
    let key_text = String::from_utf8(keys.stdout).unwrap();
    let recipient = key_text
        .lines()
        .find_map(|line| line.strip_prefix("# public key: "))
        .expect("age-keygen prints recipient")
        .to_string();
    fs::create_dir_all(dir.path().join(".config/age")).unwrap();
    fs::write(dir.path().join(".config/age/keys.txt"), &key_text).unwrap();
    fs::write(dir.path().join(".age-recipients"), recipient).unwrap();
    fs::write(dir.path().join(".env"), "TOKEN=example\n").unwrap();

    let mut encrypt = Command::cargo_bin("sealhook").unwrap();
    encrypt
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .arg("encrypt")
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypt: .env -> .env.age"));

    assert!(dir.path().join(".env.age").exists());
    fs::remove_file(dir.path().join(".env")).unwrap();

    let mut decrypt = Command::cargo_bin("sealhook").unwrap();
    decrypt
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .arg("decrypt")
        .assert()
        .success()
        .stdout(predicate::str::contains("decrypt: .env.age -> .env"));

    assert_eq!(
        fs::read_to_string(dir.path().join(".env")).unwrap(),
        "TOKEN=example\n"
    );
}
