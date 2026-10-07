#![cfg(all(unix, feature = "system-gss"))]

use std::sync::Arc;

use libgssapi::{
    context::{ClientCtx, CtxFlags, SecurityContext},
    credential::{Cred, CredUsage},
    name::Name,
    oid::{GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL, OidSet},
};
use naos_nfs::{
    rpcsec_gss::{
        RpcSecGssAcceptRequest, RpcSecGssAcceptResult, RpcSecGssAcceptor,
        StatefulRpcSecGssAcceptor,
    },
    system_gss::SystemGssHandshakeProvider,
};

#[test]
fn real_kerberos_context_negotiates_and_exchanges_mics() {
    let Ok(service_principal) = std::env::var("NAOS_GSS_TEST_SERVICE_PRINCIPAL") else {
        eprintln!("NAOS_GSS_TEST_SERVICE_PRINCIPAL is unset; skipping real Kerberos test");
        return;
    };
    let expected_client = std::env::var("NAOS_GSS_TEST_CLIENT_PRINCIPAL")
        .expect("real Kerberos test requires NAOS_GSS_TEST_CLIENT_PRINCIPAL");

    let mechanisms = OidSet::singleton(GSS_MECH_KRB5).expect("build Kerberos mechanism set");
    let credential = Cred::acquire(
        None,
        None,
        CredUsage::Initiate,
        Some(&mechanisms),
    )
    .expect("acquire Kerberos initiator credential from the configured ccache");
    let target = Name::new(
        service_principal.as_bytes(),
        Some(GSS_NT_KRB5_PRINCIPAL),
    )
    .expect("import Kerberos service principal")
    .canonicalize(Some(GSS_MECH_KRB5))
    .expect("canonicalize Kerberos service principal");

    let flags = CtxFlags::GSS_C_MUTUAL_FLAG
        | CtxFlags::GSS_C_REPLAY_FLAG
        | CtxFlags::GSS_C_SEQUENCE_FLAG
        | CtxFlags::GSS_C_INTEG_FLAG;
    let mut client = ClientCtx::new(
        Some(credential),
        target,
        flags,
        Some(GSS_MECH_KRB5),
    );
    let provider = Arc::new(
        SystemGssHandshakeProvider::new(&service_principal)
            .expect("acquire Kerberos acceptor credential from the configured keytab"),
    );
    let acceptor =
        StatefulRpcSecGssAcceptor::new(provider, 128).expect("configure RPCSEC_GSS acceptor");

    let mut client_token = client
        .step(None, None)
        .expect("produce initial Kerberos GSS token")
        .expect("Kerberos initiator must produce an initial token")
        .to_vec();
    let mut handle: Option<Vec<u8>> = None;
    let security = loop {
        let request = match handle.as_ref() {
            None => RpcSecGssAcceptRequest::Init {
                token: std::mem::take(&mut client_token),
            },
            Some(handle) => RpcSecGssAcceptRequest::Continue {
                handle: handle.clone(),
                token: std::mem::take(&mut client_token),
            },
        };

        match acceptor.accept(request).expect("run Kerberos acceptor step") {
            RpcSecGssAcceptResult::Continue {
                handle: next_handle,
                token,
                ..
            } => {
                assert!(!next_handle.is_empty(), "continue handle must not be empty");
                assert!(!token.is_empty(), "continue token must not be empty");
                if let Some(current) = handle.as_ref() {
                    assert_eq!(&next_handle, current, "continue handle must stay stable");
                }
                handle = Some(next_handle);
                client_token = client
                    .step(Some(&token), None)
                    .expect("continue Kerberos initiator context")
                    .expect("client must return another token while server continues")
                    .to_vec();
            }
            RpcSecGssAcceptResult::Complete {
                handle: completed_handle,
                token,
                security,
                ..
            } => {
                assert!(!completed_handle.is_empty(), "complete handle must not be empty");
                if let Some(current) = handle.as_ref() {
                    assert_eq!(&completed_handle, current, "complete handle must stay stable");
                }
                if !token.is_empty() {
                    let final_token = client
                        .step(Some(&token), None)
                        .expect("complete Kerberos initiator context");
                    assert!(
                        final_token.is_none(),
                        "Kerberos initiator unexpectedly produced a token after server completion"
                    );
                }
                assert!(client.is_complete(), "Kerberos initiator context must complete");
                break security;
            }
            RpcSecGssAcceptResult::Failure {
                gss_major,
                gss_minor,
            } => {
                panic!(
                    "Kerberos acceptor failed: major=0x{gss_major:08x} minor={gss_minor}"
                );
            }
        }
    };

    assert_eq!(
        security.principal(),
        expected_client,
        "server must expose the authenticated Kerberos client principal"
    );

    let client_message = b"rpcsec-gss client mic";
    let client_mic = client
        .get_mic(client_message)
        .expect("create client MIC")
        .to_vec();
    security
        .verify_mic(client_message, &client_mic)
        .expect("server verifies client MIC");

    let server_message = b"rpcsec-gss server mic";
    let server_mic = security
        .get_mic(server_message)
        .expect("create server MIC");
    client
        .verify_mic(server_message, &server_mic)
        .expect("client verifies server MIC");

    assert!(
        !security.supports_privacy(),
        "system GSS provider must remain fail-closed for krb5p until confidentiality state is verified"
    );
}
