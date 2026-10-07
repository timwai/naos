#![cfg(all(unix, feature = "system-gss"))]

use std::{env, sync::Arc};

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

#[test]
fn real_kerberos_context_establishes_and_round_trips_mic() {
    if env::var_os("NAOS_TEST_KERBEROS_REALM").is_none() {
        eprintln!("skipping real Kerberos smoke; NAOS_TEST_KERBEROS_REALM is not set");
        return;
    }

    let service_principal =
        env::var("NAOS_TEST_KERBEROS_SERVICE_PRINCIPAL").expect("service principal");
    let client_principal =
        env::var("NAOS_TEST_KERBEROS_CLIENT_PRINCIPAL").expect("client principal");

    let mechanisms = OidSet::singleton(GSS_MECH_KRB5).expect("Kerberos mechanism");
    let target = Name::new(
        service_principal.as_bytes(),
        Some(GSS_NT_KRB5_PRINCIPAL),
    )
    .expect("import service principal")
    .canonicalize(Some(GSS_MECH_KRB5))
    .expect("canonicalize service principal");
    let client_name = Name::new(
        client_principal.as_bytes(),
        Some(GSS_NT_KRB5_PRINCIPAL),
    )
    .expect("import client principal")
    .canonicalize(Some(GSS_MECH_KRB5))
    .expect("canonicalize client principal");
    let client_credential = Cred::acquire(
        Some(&client_name),
        None,
        CredUsage::Initiate,
        Some(&mechanisms),
    )
    .expect("acquire client credential from ccache");
    let mut client = ClientCtx::new(
        Some(client_credential),
        target,
        CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_INTEG_FLAG,
        Some(GSS_MECH_KRB5),
    );

    let provider = Arc::new(
        SystemGssHandshakeProvider::new(&service_principal)
            .expect("acquire server credential from keytab"),
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
