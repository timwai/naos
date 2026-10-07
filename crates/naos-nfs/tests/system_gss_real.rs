#![cfg(all(target_os = "linux", feature = "system-gss"))]

use std::{
    env, fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use libgssapi::{
    context::{ClientCtx, CtxFlags, SecurityContext},
    credential::{Cred, CredUsage},
    name::Name,
    oid::{GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL, OidSet},
};
use naos_nfs::{
    rpcsec_gss::{
        RpcSecGssAcceptRequest, RpcSecGssAcceptResult, RpcSecGssAcceptor,
        RpcSecGssSecurityError, StatefulRpcSecGssAcceptor,
    },
    system_gss::SystemGssHandshakeProvider,
};

struct TestKdc {
    _tempdir: tempfile::TempDir,
    child: Child,
    config_path: PathBuf,
    keytab_path: PathBuf,
    realm: String,
}

impl TestKdc {
    fn new() -> Self {
        let tempdir = tempfile::tempdir().expect("create Kerberos tempdir");
        let dir = tempdir.path().to_path_buf();
        let realm = "EXAMPLE.COM".to_owned();
        let port = free_port();
        let config_path = dir.join("krb5.conf");
        let keytab_path = dir.join("naos.keytab");

        fs::write(&config_path, build_config(&dir, port, &realm))
            .expect("write Kerberos config");
        fs::write(dir.join("kadm5.acl"), "*/admin@EXAMPLE.COM\t*\n")
            .expect("write Kerberos ACL");

        run_assert(
            Command::new("kdb5_util")
                .args(["create", "-s", "-P", "masterpass", "-r", &realm])
                .env("KRB5_CONFIG", &config_path)
                .env("KRB5_KDC_PROFILE", &config_path),
            "create Kerberos database",
        );
        run_assert(
            Command::new("kadmin.local")
                .args(["-q", "addprinc -pw testpass testuser@EXAMPLE.COM"])
                .env("KRB5_CONFIG", &config_path)
                .env("KRB5_KDC_PROFILE", &config_path),
            "create Kerberos client principal",
        );
        run_assert(
            Command::new("kadmin.local")
                .args([
                    "-q",
                    "addprinc -randkey nfs/test.example.com@EXAMPLE.COM",
                ])
                .env("KRB5_CONFIG", &config_path)
                .env("KRB5_KDC_PROFILE", &config_path),
            "create Kerberos service principal",
        );
        run_assert(
            Command::new("kadmin.local")
                .args([
                    "-q",
                    &format!(
                        "ktadd -k {} nfs/test.example.com@EXAMPLE.COM",
                        keytab_path.display()
                    ),
                ])
                .env("KRB5_CONFIG", &config_path)
                .env("KRB5_KDC_PROFILE", &config_path),
            "export Kerberos service keytab",
        );

        let child = Command::new("krb5kdc")
            .args(["-n", "-P"])
            .arg(dir.join("kdc.pid"))
            .args(["-r", &realm])
            .env("KRB5_CONFIG", &config_path)
            .env("KRB5_KDC_PROFILE", &config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start temporary MIT Kerberos KDC");
        wait_for_port(port);

        Self {
            _tempdir: tempdir,
            child,
            config_path,
            keytab_path,
            realm,
        }
    }

    fn apply_env(&self) {
        // This integration-test binary contains a single test, so no other
        // thread mutates the process-wide Kerberos environment concurrently.
        unsafe {
            env::set_var("KRB5_CONFIG", &self.config_path);
            env::set_var(
                "KRB5_KTNAME",
                format!("FILE:{}", self.keytab_path.display()),
            );
            env::set_var("KRB5RCACHENAME", "none:");
        }
    }
}

impl Drop for TestKdc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn real_kerberos_context_establishes_and_round_trips_mic() {
    if env::var_os("NAOS_TEST_KERBEROS_REALM").is_none() {
        eprintln!("skipping real Kerberos smoke; NAOS_TEST_KERBEROS_REALM is not set");
        return;
    }

    let kdc = TestKdc::new();
    kdc.apply_env();

    let service_principal = format!("nfs/test.example.com@{}", kdc.realm);
    let client_principal = format!("testuser@{}", kdc.realm);
    let mechanisms = OidSet::singleton(GSS_MECH_KRB5).expect("Kerberos mechanism");

    let target = Name::new(service_principal.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))
        .expect("import service principal")
        .canonicalize(Some(GSS_MECH_KRB5))
        .expect("canonicalize service principal");
    let client_name = Name::new(client_principal.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))
        .expect("import client principal")
        .canonicalize(Some(GSS_MECH_KRB5))
        .expect("canonicalize client principal");
    let client_credential = Cred::acquire_with_password(
        Some(&client_name),
        "testpass",
        None,
        CredUsage::Initiate,
        Some(&mechanisms),
    )
    .expect("acquire client credential from temporary KDC");
    let mut client = ClientCtx::new(
        Some(client_credential),
        target,
        CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_INTEG_FLAG,
        Some(GSS_MECH_KRB5),
    );

    let provider = Arc::new(
        SystemGssHandshakeProvider::new(&service_principal)
            .expect("acquire server credential from temporary keytab"),
    );
    let acceptor =
        StatefulRpcSecGssAcceptor::new(provider, 32).expect("configure stateful acceptor");

    let mut handle: Option<Vec<u8>> = None;
    let mut server_token: Option<Vec<u8>> = None;
    let mut established = None;

    for step in 1..=8 {
        let client_output = client
            .step(server_token.as_deref(), None)
            .unwrap_or_else(|error| panic!("client GSS step {step}: {error}"));
        server_token = None;

        let Some(client_token) = client_output else {
            if client.is_complete() && established.is_some() {
                break;
            }
            panic!("client completed before server context was established");
        };

        let request = match &handle {
            None => RpcSecGssAcceptRequest::Init {
                token: client_token.to_vec(),
            },
            Some(handle) => RpcSecGssAcceptRequest::Continue {
                handle: handle.clone(),
                token: client_token.to_vec(),
            },
        };

        match acceptor.accept(request).expect("accept Kerberos GSS token") {
            RpcSecGssAcceptResult::Continue {
                handle: next_handle,
                seq_window,
                token,
                ..
            } => {
                assert_eq!(seq_window, 32);
                if let Some(previous) = &handle {
                    assert_eq!(&next_handle, previous, "GSS context handle changed");
                }
                handle = Some(next_handle);
                assert!(!token.is_empty(), "continuation must return a GSS token");
                server_token = Some(token);
            }
            RpcSecGssAcceptResult::Complete {
                handle: completed_handle,
                seq_window,
                token,
                security,
                ..
            } => {
                assert_eq!(seq_window, 32);
                if let Some(previous) = &handle {
                    assert_eq!(&completed_handle, previous, "GSS context handle changed");
                }
                handle = Some(completed_handle);
                established = Some(security);

                if !token.is_empty() {
                    let final_output = client
                        .step(Some(&token), None)
                        .unwrap_or_else(|error| panic!("final client GSS step: {error}"));
                    assert!(
                        final_output.is_none(),
                        "client emitted an unexpected token after acceptor completion"
                    );
                }
                break;
            }
            RpcSecGssAcceptResult::Failure {
                gss_major,
                gss_minor,
            } => panic!(
                "server GSS accept failed: major=0x{gss_major:08x} minor={gss_minor}"
            ),
        }
    }

    let security = established.expect("server GSS context was not established");
    assert!(client.is_complete(), "client GSS context is incomplete");
    assert!(!handle.expect("RPCSEC_GSS handle").is_empty());
    assert_eq!(security.principal(), client_principal);
    assert!(
        !security.supports_privacy(),
        "system GSS provider must keep krb5p fail-closed until privacy is enabled"
    );

    let message = b"naos real Kerberos MIC smoke";
    let client_mic = client.get_mic(message).expect("client get_mic");
    security
        .verify_mic(message, &client_mic)
        .expect("server verifies client MIC");

    let server_mic = security.get_mic(message).expect("server get_mic");
    client
        .verify_mic(message, &server_mic)
        .expect("client verifies server MIC");

    let mut corrupted = client_mic.to_vec();
    let last = corrupted.last_mut().expect("non-empty MIC");
    *last ^= 1;
    assert_eq!(
        security.verify_mic(message, &corrupted),
        Err(RpcSecGssSecurityError::BadMic)
    );
}

fn build_config(dir: &Path, port: u16, realm: &str) -> String {
    format!(
        r#"[libdefaults]
    default_realm = {realm}
    dns_canonicalize_hostname = false
    rdns = false
    forwardable = true
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    {realm} = {{
        kdc = 127.0.0.1:{port}
        admin_server = 127.0.0.1
        database_name = {database}
        admin_keytab = FILE:{admin_keytab}
        acl_file = {acl}
        key_stash_file = {stash}
        max_life = 1h
        max_renewable_life = 1h
    }}

[kdcdefaults]
    kdc_ports = {port}
    kdc_tcp_ports = {port}

[domain_realm]
    test.example.com = {realm}
    .example.com = {realm}
"#,
        database = dir.join("principal").display(),
        admin_keytab = dir.join("kadm5.keytab").display(),
        acl = dir.join("kadm5.acl").display(),
        stash = dir.join(".k5stash").display(),
    )
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral KDC port");
    listener.local_addr().expect("local KDC address").port()
}

fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("temporary KDC did not start on port {port}");
}

fn run_assert(command: &mut Command, what: &str) {
    let output = command.output().unwrap_or_else(|error| panic!("{what}: {error}"));
    assert!(
        output.status.success(),
        "{what} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
