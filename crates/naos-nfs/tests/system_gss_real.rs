#![cfg(all(target_os = "linux", feature = "system-gss"))]

use std::{
    env, fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use async_trait::async_trait;

use libgssapi::{
    context::{ClientCtx, CtxFlags, SecurityContext},
    credential::{Cred, CredUsage},
    name::Name,
    oid::{GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL, OidSet},
};
use naos_core::{
    acl::{AclRule, Permission, Subject},
    nfs::{NfsAccessRepository, NfsBinding, NfsBindingRepository, NfsExport, NfsRepositoryError},
    path::RelativePath,
};
use naos_nfs::{
    mount::{MOUNT_PROGRAM, MOUNT_VERSION},
    nfs3::{NFS_PROGRAM, NFS_VERSION},
    rpc::{
        AUTH_NONE, GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED, MAX_AUTH_BYTES, RPC_VERSION, RPCSEC_GSS,
        RPCSEC_GSS_CONTINUE_INIT, RPCSEC_GSS_DATA, RPCSEC_GSS_INIT, RPCSEC_GSS_SVC_INTEGRITY,
        RPCSEC_GSS_SVC_NONE, RPCSEC_GSS_VERSION_1, RpcCall, RpcCredential, RpcSecGssCredential,
        RpcSecGssInitResult, RpcVerifier, decode_rpcsec_gss_init_result,
        decode_rpcsec_gss_integrity_body, encode_rpcsec_gss_init_token,
        encode_rpcsec_gss_integrity_body, encode_rpcsec_gss_plaintext, rpcsec_gss_u32_mic_input,
    },
    rpcsec_gss::{
        RpcSecGssAcceptRequest, RpcSecGssAcceptResult, RpcSecGssAcceptor, RpcSecGssContextRegistry,
        RpcSecGssDataError, RpcSecGssRegistryError, RpcSecGssSecurityError,
        StatefulRpcSecGssAcceptor, accept_context_call, authenticate_data_call,
    },
    server::{NfsServer, NfsServerConfig},
    system_gss::SystemGssHandshakeProvider,
    transport::{read_record, write_record},
    xdr::{XdrReader, XdrWriter},
};
use tokio::{net::TcpStream, sync::watch};

struct FakeRepository {
    export: NfsExport,
    rules: Vec<AclRule>,
    principal: String,
}

#[async_trait]
impl NfsBindingRepository for FakeRepository {
    async fn find_enabled_nfs_export_by_name(
        &self,
        name: &str,
    ) -> Result<Option<NfsExport>, NfsRepositoryError> {
        Ok((self.export.name == name).then(|| self.export.clone()))
    }

    async fn list_enabled_nfs_exports(&self) -> Result<Vec<NfsExport>, NfsRepositoryError> {
        Ok(vec![self.export.clone()])
    }

    async fn nfs_share_exists(&self, share_id: &str) -> Result<bool, NfsRepositoryError> {
        Ok(self.export.id == share_id)
    }

    async fn nfs_user_exists(&self, user_id: &str) -> Result<bool, NfsRepositoryError> {
        Ok(user_id == "usr_alice")
    }

    async fn resolve_nfs_krb_principal(
        &self,
        principal: &str,
    ) -> Result<Option<String>, NfsRepositoryError> {
        Ok((principal == self.principal).then(|| "usr_alice".to_owned()))
    }

    async fn list_nfs_bindings(
        &self,
        _share_id: &str,
    ) -> Result<Vec<NfsBinding>, NfsRepositoryError> {
        Ok(Vec::new())
    }

    async fn insert_nfs_binding(&self, _binding: &NfsBinding) -> Result<(), NfsRepositoryError> {
        Err(NfsRepositoryError::Unavailable)
    }

    async fn update_nfs_binding(&self, _binding: &NfsBinding) -> Result<bool, NfsRepositoryError> {
        Err(NfsRepositoryError::Unavailable)
    }

    async fn delete_nfs_binding(
        &self,
        _share_id: &str,
        _binding_id: &str,
    ) -> Result<bool, NfsRepositoryError> {
        Err(NfsRepositoryError::Unavailable)
    }
}

#[async_trait]
impl NfsAccessRepository for FakeRepository {
    async fn list_nfs_acl_rules(&self, share_id: &str) -> Result<Vec<AclRule>, NfsRepositoryError> {
        Ok(if self.export.id == share_id {
            self.rules.clone()
        } else {
            Vec::new()
        })
    }

    async fn nfs_group_ids_for_user(
        &self,
        _user_id: &str,
    ) -> Result<Vec<String>, NfsRepositoryError> {
        Ok(Vec::new())
    }
}

fn repository(root: &Path, principal: &str) -> Arc<FakeRepository> {
    let export = NfsExport {
        id: "shr_media".to_owned(),
        name: "media".to_owned(),
        canonical_path: fs::canonicalize(root)
            .expect("canonicalize NFS export root")
            .to_string_lossy()
            .into_owned(),
        generation: 1,
    };
    Arc::new(FakeRepository {
        rules: vec![AclRule {
            path: RelativePath::root(),
            subject: Subject::User("usr_alice".to_owned()),
            permission: Permission::ReadWrite,
            inherit: true,
        }],
        export,
        principal: principal.to_owned(),
    })
}

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

        fs::write(&config_path, build_config(&dir, port, &realm)).expect("write Kerberos config");
        fs::write(dir.join("kadm5.acl"), "*/admin@EXAMPLE.COM\t*\n").expect("write Kerberos ACL");

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
                .args(["-q", "addprinc -randkey nfs/test.example.com@EXAMPLE.COM"])
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

#[tokio::test(flavor = "current_thread")]
async fn real_kerberos_context_establishes_and_round_trips_mic() {
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
            } => panic!("server GSS accept failed: major=0x{gss_major:08x} minor={gss_minor}"),
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

    let wire_target = Name::new(service_principal.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))
        .expect("import wire service principal")
        .canonicalize(Some(GSS_MECH_KRB5))
        .expect("canonicalize wire service principal");
    let wire_client_name = Name::new(client_principal.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))
        .expect("import wire client principal")
        .canonicalize(Some(GSS_MECH_KRB5))
        .expect("canonicalize wire client principal");
    let wire_client_credential = Cred::acquire_with_password(
        Some(&wire_client_name),
        "testpass",
        None,
        CredUsage::Initiate,
        Some(&mechanisms),
    )
    .expect("acquire wire client credential");
    let mut wire_client = ClientCtx::new(
        Some(wire_client_credential),
        wire_target,
        CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_INTEG_FLAG,
        Some(GSS_MECH_KRB5),
    );
    let wire_provider = Arc::new(
        SystemGssHandshakeProvider::new(&service_principal)
            .expect("acquire wire server credential"),
    );
    let wire_acceptor =
        StatefulRpcSecGssAcceptor::new(wire_provider, 64).expect("configure wire acceptor");
    let registry = RpcSecGssContextRegistry::new();

    let mut wire_handle = Vec::new();
    let mut wire_server_token: Option<Vec<u8>> = None;
    let mut gss_proc = RPCSEC_GSS_INIT;
    let mut completed_verifier = None;

    for step in 1..=8 {
        let client_output = wire_client
            .step(wire_server_token.as_deref(), None)
            .unwrap_or_else(|error| panic!("wire client GSS step {step}: {error}"));
        wire_server_token = None;

        let Some(client_token) = client_output else {
            if wire_client.is_complete() && completed_verifier.is_some() {
                break;
            }
            panic!("wire client completed before RPCSEC_GSS context creation");
        };

        let call = context_call(100 + step, gss_proc, &wire_handle, &client_token);
        let reply = accept_context_call(&registry, &wire_acceptor, &call)
            .await
            .unwrap_or_else(|error| panic!("RPCSEC_GSS context step {step}: {error}"));
        let (verifier, result) = decode_context_reply(100 + step, &reply);

        assert_eq!(result.seq_window, 64);
        if wire_handle.is_empty() {
            assert!(!result.handle.is_empty());
        } else {
            assert_eq!(result.handle, wire_handle, "RPCSEC_GSS handle changed");
        }
        wire_handle = result.handle.clone();

        match result.gss_major {
            GSS_S_CONTINUE_NEEDED => {
                assert_eq!(verifier.flavor, AUTH_NONE);
                assert!(verifier.body.is_empty());
                assert!(!registry.contains(&wire_handle).await);
                assert!(!result.token.is_empty());
                wire_server_token = Some(result.token);
                gss_proc = RPCSEC_GSS_CONTINUE_INIT;
            }
            GSS_S_COMPLETE => {
                assert_eq!(verifier.flavor, RPCSEC_GSS);
                if !result.token.is_empty() {
                    let final_output = wire_client
                        .step(Some(&result.token), None)
                        .unwrap_or_else(|error| panic!("wire final client GSS step: {error}"));
                    assert!(final_output.is_none());
                }
                assert!(wire_client.is_complete());
                wire_client
                    .verify_mic(&rpcsec_gss_u32_mic_input(result.seq_window), &verifier.body)
                    .expect("verify RPCSEC_GSS init reply verifier");
                completed_verifier = Some(verifier);
                break;
            }
            major => panic!(
                "unexpected RPCSEC_GSS GSS status: major=0x{major:08x} minor={}",
                result.gss_minor
            ),
        }
    }

    assert!(
        completed_verifier.is_some(),
        "RPCSEC_GSS context did not complete"
    );
    let registered = registry
        .get(&wire_handle)
        .await
        .expect("completed context registered");
    assert_eq!(registered.principal(), client_principal);
    let wire_mic = wire_client
        .get_mic(b"registered context")
        .expect("wire client MIC");
    registered
        .verify_mic(b"registered context", &wire_mic)
        .expect("registered context verifies client MIC");

    let none_seq = 7;
    let none_header = b"rpcsec-gss-real-none-header";
    let none_header_mic = wire_client
        .get_mic(none_header)
        .expect("client header MIC for svc_none");
    let none_call = data_call(
        200,
        &wire_handle,
        none_seq,
        RPCSEC_GSS_SVC_NONE,
        none_header,
        b"real-none-arguments".to_vec(),
        &none_header_mic,
    );
    let none_authenticated = authenticate_data_call(&registry, &none_call)
        .await
        .expect("authenticate real svc_none request");
    assert_eq!(none_authenticated.principal(), client_principal);
    assert_eq!(none_authenticated.arguments(), b"real-none-arguments");

    let none_reply = none_authenticated
        .protect_reply(b"real-none-reply")
        .expect("protect real svc_none reply");
    assert_eq!(none_reply.verifier.flavor, RPCSEC_GSS);
    wire_client
        .verify_mic(
            &rpcsec_gss_u32_mic_input(none_seq),
            &none_reply.verifier.body,
        )
        .expect("verify real svc_none reply verifier");
    assert_eq!(none_reply.body, b"real-none-reply");

    assert!(matches!(
        authenticate_data_call(&registry, &none_call).await,
        Err(RpcSecGssDataError::Registry(RpcSecGssRegistryError::Replay))
    ));

    let integrity_seq = 8;
    let integrity_arguments = b"real-integrity-arguments";
    let integrity_plaintext = encode_rpcsec_gss_plaintext(integrity_seq, integrity_arguments);
    let integrity_checksum = wire_client
        .get_mic(&integrity_plaintext)
        .expect("client integrity body MIC");
    let integrity_body =
        encode_rpcsec_gss_integrity_body(integrity_seq, integrity_arguments, &integrity_checksum)
            .expect("encode real integrity request");
    let integrity_header = b"rpcsec-gss-real-integrity-header";
    let integrity_header_mic = wire_client
        .get_mic(integrity_header)
        .expect("client header MIC for svc_integrity");
    let integrity_call = data_call(
        201,
        &wire_handle,
        integrity_seq,
        RPCSEC_GSS_SVC_INTEGRITY,
        integrity_header,
        integrity_body,
        &integrity_header_mic,
    );
    let integrity_authenticated = authenticate_data_call(&registry, &integrity_call)
        .await
        .expect("authenticate real svc_integrity request");
    assert_eq!(integrity_authenticated.principal(), client_principal);
    assert_eq!(integrity_authenticated.arguments(), integrity_arguments);

    let integrity_reply = integrity_authenticated
        .protect_reply(b"real-integrity-reply")
        .expect("protect real svc_integrity reply");
    wire_client
        .verify_mic(
            &rpcsec_gss_u32_mic_input(integrity_seq),
            &integrity_reply.verifier.body,
        )
        .expect("verify real integrity reply verifier");
    let decoded_reply = decode_rpcsec_gss_integrity_body(&integrity_reply.body, integrity_seq)
        .expect("decode real integrity reply");
    assert_eq!(decoded_reply.arguments, b"real-integrity-reply");
    let reply_plaintext = encode_rpcsec_gss_plaintext(integrity_seq, &decoded_reply.arguments);
    wire_client
        .verify_mic(&reply_plaintext, &decoded_reply.checksum)
        .expect("verify real integrity reply checksum");

    let export_root = tempfile::tempdir().expect("create real NFS export root");
    let server_provider = Arc::new(
        SystemGssHandshakeProvider::new(&service_principal)
            .expect("acquire TCP server GSS credential"),
    );
    let server_acceptor = Arc::new(
        StatefulRpcSecGssAcceptor::new(server_provider, 64)
            .expect("configure TCP RPCSEC_GSS acceptor"),
    );
    let server = NfsServer::bind_with_rpcsec_gss(
        repository(export_root.path(), &client_principal),
        NfsServerConfig {
            listen: "127.0.0.1".parse().expect("loopback address"),
            nfs_port: 0,
            mount_port: 0,
            nlm_port: 0,
            nsm_port: 0,
            rpcbind_address: None,
        },
        server_acceptor,
    )
    .await
    .expect("bind real Kerberos NFS server");
    let mount_address = server.mount_address().expect("MOUNT address");
    let nfs_address = server.nfs_address().expect("NFS address");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let tcp_target = Name::new(service_principal.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))
        .expect("import TCP service principal")
        .canonicalize(Some(GSS_MECH_KRB5))
        .expect("canonicalize TCP service principal");
    let tcp_client_name = Name::new(client_principal.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))
        .expect("import TCP client principal")
        .canonicalize(Some(GSS_MECH_KRB5))
        .expect("canonicalize TCP client principal");
    let tcp_mechanisms = OidSet::singleton(GSS_MECH_KRB5).expect("TCP Kerberos mechanism");
    let tcp_client_credential = Cred::acquire_with_password(
        Some(&tcp_client_name),
        "testpass",
        None,
        CredUsage::Initiate,
        Some(&tcp_mechanisms),
    )
    .expect("acquire TCP client credential");
    let mut tcp_client = ClientCtx::new(
        Some(tcp_client_credential),
        tcp_target,
        CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_INTEG_FLAG,
        Some(GSS_MECH_KRB5),
    );

    let mut tcp_handle = Vec::new();
    let mut tcp_server_token: Option<Vec<u8>> = None;
    let mut tcp_gss_proc = RPCSEC_GSS_INIT;
    let mut tcp_complete = false;

    for step in 1..=8 {
        let client_output = tcp_client
            .step(tcp_server_token.as_deref(), None)
            .unwrap_or_else(|error| panic!("TCP client GSS step {step}: {error}"));
        tcp_server_token = None;

        let Some(client_token) = client_output else {
            if tcp_client.is_complete() && tcp_complete {
                break;
            }
            panic!("TCP client completed before server context creation");
        };

        let xid = 300 + step;
        let request = rpcsec_gss_context_wire_call(
            xid,
            MOUNT_PROGRAM,
            MOUNT_VERSION,
            tcp_gss_proc,
            &tcp_handle,
            &client_token,
        );
        let reply = rpc_round_trip(mount_address, request).await;
        let (verifier, result) = decode_context_reply(xid, &reply);
        assert_eq!(result.seq_window, 64);
        if tcp_handle.is_empty() {
            assert!(!result.handle.is_empty());
        } else {
            assert_eq!(result.handle, tcp_handle, "TCP RPCSEC_GSS handle changed");
        }
        tcp_handle = result.handle.clone();

        match result.gss_major {
            GSS_S_CONTINUE_NEEDED => {
                assert_eq!(verifier.flavor, AUTH_NONE);
                assert!(verifier.body.is_empty());
                tcp_server_token = Some(result.token);
                tcp_gss_proc = RPCSEC_GSS_CONTINUE_INIT;
            }
            GSS_S_COMPLETE => {
                if !result.token.is_empty() {
                    let final_output = tcp_client
                        .step(Some(&result.token), None)
                        .unwrap_or_else(|error| panic!("TCP final client GSS step: {error}"));
                    assert!(final_output.is_none());
                }
                assert!(tcp_client.is_complete());
                tcp_client
                    .verify_mic(&rpcsec_gss_u32_mic_input(result.seq_window), &verifier.body)
                    .expect("verify TCP init reply verifier");
                tcp_complete = true;
                break;
            }
            major => panic!(
                "TCP RPCSEC_GSS context creation failed: major=0x{major:08x} minor={}",
                result.gss_minor
            ),
        }
    }
    assert!(tcp_complete, "TCP RPCSEC_GSS context did not complete");

    let mut mount_arguments = XdrWriter::new();
    mount_arguments.string("/media").expect("encode MOUNT path");
    let mount_request = rpcsec_gss_wire_data_call(
        &mut tcp_client,
        400,
        MOUNT_PROGRAM,
        MOUNT_VERSION,
        1,
        1,
        RPCSEC_GSS_SVC_NONE,
        &tcp_handle,
        &mount_arguments.into_bytes(),
    );
    let mount_reply = rpc_round_trip(mount_address, mount_request).await;
    let mount_body =
        decode_wire_data_reply(&mut tcp_client, 400, 1, RPCSEC_GSS_SVC_NONE, &mount_reply);
    let mut mount_reader = XdrReader::new(&mount_body);
    assert_eq!(mount_reader.u32().expect("MOUNT status"), 0);
    let root_handle = mount_reader.opaque(64).expect("MOUNT root file handle");
    assert!(!root_handle.is_empty());
    assert_eq!(
        mount_reader.u32_array(4).expect("MOUNT auth flavors"),
        vec![RPCSEC_GSS]
    );
    mount_reader.finish().expect("MOUNT reply trailing data");

    let mut getattr_arguments = XdrWriter::new();
    getattr_arguments
        .opaque(&root_handle)
        .expect("encode GETATTR file handle");
    let getattr_request = rpcsec_gss_wire_data_call(
        &mut tcp_client,
        401,
        NFS_PROGRAM,
        NFS_VERSION,
        1,
        2,
        RPCSEC_GSS_SVC_INTEGRITY,
        &tcp_handle,
        &getattr_arguments.into_bytes(),
    );
    let getattr_reply = rpc_round_trip(nfs_address, getattr_request).await;
    let getattr_body = decode_wire_data_reply(
        &mut tcp_client,
        401,
        2,
        RPCSEC_GSS_SVC_INTEGRITY,
        &getattr_reply,
    );
    let mut getattr_reader = XdrReader::new(&getattr_body);
    assert_eq!(getattr_reader.u32().expect("GETATTR status"), 0);

    shutdown_tx.send(true).expect("request NFS server shutdown");
    server_task
        .await
        .expect("join NFS server task")
        .expect("run NFS server");
}

async fn rpc_round_trip(address: SocketAddr, request: Vec<u8>) -> Vec<u8> {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect RPC server");
    write_record(&mut stream, &request)
        .await
        .expect("write RPC record");
    read_record(&mut stream)
        .await
        .expect("read RPC record")
        .expect("RPC server closed without reply")
}

fn rpcsec_gss_context_wire_call(
    xid: u32,
    program: u32,
    version: u32,
    gss_proc: u32,
    handle: &[u8],
    token: &[u8],
) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(0);
    writer.u32(RPC_VERSION);
    writer.u32(program);
    writer.u32(version);
    writer.u32(0);

    let mut credential = XdrWriter::new();
    credential.u32(RPCSEC_GSS_VERSION_1);
    credential.u32(gss_proc);
    credential.u32(u32::MAX);
    credential.u32(u32::MAX);
    credential
        .opaque(handle)
        .expect("encode context creation handle");
    writer.u32(RPCSEC_GSS);
    writer
        .opaque(&credential.into_bytes())
        .expect("encode RPCSEC_GSS context credential");

    writer.u32(AUTH_NONE);
    writer.opaque(&[]).expect("encode AUTH_NONE verifier");

    let mut request = writer.into_bytes();
    request.extend_from_slice(&encode_rpcsec_gss_init_token(token).expect("encode GSS init token"));
    request
}

fn rpcsec_gss_wire_data_call(
    client: &mut ClientCtx,
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
    seq_num: u32,
    service: u32,
    handle: &[u8],
    arguments: &[u8],
) -> Vec<u8> {
    let body = match service {
        RPCSEC_GSS_SVC_NONE => arguments.to_vec(),
        RPCSEC_GSS_SVC_INTEGRITY => {
            let plaintext = encode_rpcsec_gss_plaintext(seq_num, arguments);
            let checksum = client.get_mic(&plaintext).expect("client request body MIC");
            encode_rpcsec_gss_integrity_body(seq_num, arguments, &checksum)
                .expect("encode integrity request body")
        }
        _ => panic!("unsupported real TCP service {service}"),
    };

    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(0);
    writer.u32(RPC_VERSION);
    writer.u32(program);
    writer.u32(version);
    writer.u32(procedure);

    let mut credential = XdrWriter::new();
    credential.u32(RPCSEC_GSS_VERSION_1);
    credential.u32(RPCSEC_GSS_DATA);
    credential.u32(seq_num);
    credential.u32(service);
    credential
        .opaque(handle)
        .expect("encode DATA context handle");
    writer.u32(RPCSEC_GSS);
    writer
        .opaque(&credential.into_bytes())
        .expect("encode DATA credential");

    let header = writer.into_bytes();
    let header_mic = client.get_mic(&header).expect("client RPC header MIC");
    let mut verifier = XdrWriter::new();
    verifier.u32(RPCSEC_GSS);
    verifier
        .opaque(&header_mic)
        .expect("encode RPCSEC_GSS verifier");

    let mut request = header;
    request.extend_from_slice(&verifier.into_bytes());
    request.extend_from_slice(&body);
    request
}

fn decode_wire_data_reply(
    client: &mut ClientCtx,
    xid: u32,
    seq_num: u32,
    service: u32,
    reply: &[u8],
) -> Vec<u8> {
    let mut reader = XdrReader::new(reply);
    assert_eq!(reader.u32().expect("reply xid"), xid);
    assert_eq!(reader.u32().expect("reply direction"), 1);
    assert_eq!(reader.u32().expect("accepted reply"), 0);
    assert_eq!(reader.u32().expect("reply verifier flavor"), RPCSEC_GSS);
    let verifier = reader
        .opaque(MAX_AUTH_BYTES)
        .expect("RPCSEC_GSS reply verifier");
    client
        .verify_mic(&rpcsec_gss_u32_mic_input(seq_num), &verifier)
        .expect("verify RPCSEC_GSS DATA reply verifier");
    assert_eq!(reader.u32().expect("RPC accepted status"), 0);

    match service {
        RPCSEC_GSS_SVC_NONE => reader.remaining().to_vec(),
        RPCSEC_GSS_SVC_INTEGRITY => {
            let protected = decode_rpcsec_gss_integrity_body(reader.remaining(), seq_num)
                .expect("decode integrity reply body");
            let plaintext = encode_rpcsec_gss_plaintext(seq_num, &protected.arguments);
            client
                .verify_mic(&plaintext, &protected.checksum)
                .expect("verify integrity reply body MIC");
            protected.arguments
        }
        _ => panic!("unsupported real TCP reply service {service}"),
    }
}

fn context_call(xid: u32, gss_proc: u32, handle: &[u8], token: &[u8]) -> RpcCall {
    RpcCall {
        xid,
        program: 100003,
        version: 3,
        procedure: 0,
        credential: RpcCredential::RpcSecGss(RpcSecGssCredential {
            version: RPCSEC_GSS_VERSION_1,
            gss_proc,
            seq_num: u32::MAX,
            service: u32::MAX,
            handle: handle.to_vec(),
        }),
        verifier: RpcVerifier {
            flavor: AUTH_NONE,
            body: Vec::new(),
        },
        header_through_credential: Vec::new(),
        body: encode_rpcsec_gss_init_token(token).expect("encode RPCSEC_GSS init token"),
    }
}

fn data_call(
    xid: u32,
    handle: &[u8],
    seq_num: u32,
    service: u32,
    header_through_credential: &[u8],
    body: Vec<u8>,
    verifier: &[u8],
) -> RpcCall {
    RpcCall {
        xid,
        program: 100003,
        version: 3,
        procedure: 1,
        credential: RpcCredential::RpcSecGss(RpcSecGssCredential {
            version: RPCSEC_GSS_VERSION_1,
            gss_proc: RPCSEC_GSS_DATA,
            seq_num,
            service,
            handle: handle.to_vec(),
        }),
        verifier: RpcVerifier {
            flavor: RPCSEC_GSS,
            body: verifier.to_vec(),
        },
        header_through_credential: header_through_credential.to_vec(),
        body,
    }
}

fn decode_context_reply(xid: u32, reply: &[u8]) -> (RpcVerifier, RpcSecGssInitResult) {
    let mut reader = XdrReader::new(reply);
    assert_eq!(reader.u32().expect("reply xid"), xid);
    assert_eq!(reader.u32().expect("reply direction"), 1);
    assert_eq!(reader.u32().expect("accepted reply"), 0);
    let verifier = RpcVerifier {
        flavor: reader.u32().expect("verifier flavor"),
        body: reader
            .opaque(MAX_AUTH_BYTES)
            .expect("RPCSEC_GSS reply verifier"),
    };
    assert_eq!(reader.u32().expect("accepted status"), 0);
    let result =
        decode_rpcsec_gss_init_result(reader.remaining()).expect("decode RPCSEC_GSS init result");
    (verifier, result)
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
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{what}: {error}"));
    assert!(
        output.status.success(),
        "{what} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
