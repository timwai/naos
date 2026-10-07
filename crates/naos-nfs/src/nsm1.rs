use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use naos_core::nfs::{NfsBindingRepository, NfsRepositoryError};
use rand_core::{OsRng, RngCore};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc},
};

use crate::{
    rpc::{
        AUTH_NONE, RPC_VERSION, RpcCall, RpcDecodeError, accepted_garbage_args,
        accepted_procedure_unavailable, accepted_program_mismatch, accepted_program_unavailable,
        accepted_success, accepted_system_error, decode_call, denied_rpc_mismatch,
    },
    rpcbind::{RpcTransport, lookup_port},
    transport::{read_record, write_record},
    xdr::{XdrReader, XdrWriter},
};

pub const NSM_PROGRAM: u32 = 100024;
pub const NSM_VERSION: u32 = 1;

const SM_NULL: u32 = 0;
const SM_STAT: u32 = 1;
const SM_MON: u32 = 2;
const SM_UNMON: u32 = 3;
const SM_UNMON_ALL: u32 = 4;
const SM_SIMU_CRASH: u32 = 5;
const SM_NOTIFY: u32 = 6;

const SM_MAXSTRLEN: usize = 1024;
const SM_PRIV_SIZE: usize = 16;
const STAT_SUCC: u32 = 0;
const INITIAL_UP_STATE: u32 = 1;
const RPCBIND_PORT: u16 = 111;

#[derive(Debug, Clone, PartialEq, Eq)]
struct NsmMyId {
    name: String,
    program: u32,
    version: u32,
    procedure: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NsmMonId {
    mon_name: String,
    my_id: NsmMyId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NsmMonitor {
    client_ip: IpAddr,
    mon_id: NsmMonId,
    private: [u8; SM_PRIV_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsmNotification {
    pub client_ip: IpAddr,
    pub mon_name: String,
    pub state: u32,
}

#[derive(Debug)]
struct NsmState {
    state: u32,
    monitors: Vec<NsmMonitor>,
    notifications: Vec<NsmNotification>,
}

impl Default for NsmState {
    fn default() -> Self {
        Self::with_state(INITIAL_UP_STATE)
    }
}

impl NsmState {
    fn with_state(state: u32) -> Self {
        Self {
            state: normalize_up_state(state),
            monitors: Vec::new(),
            notifications: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct NsmV1Service {
    inner: Arc<Mutex<NsmState>>,
    notification_tx: Option<mpsc::UnboundedSender<NsmNotification>>,
    state_repository: Option<Arc<dyn NfsBindingRepository>>,
}

impl Default for NsmV1Service {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NsmState::default())),
            notification_tx: None,
            state_repository: None,
        }
    }
}

impl NsmV1Service {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_notification_sender(
        notification_tx: mpsc::UnboundedSender<NsmNotification>,
    ) -> Self {
        Self::with_state_and_notification_sender(INITIAL_UP_STATE, notification_tx)
    }

    pub fn with_state_and_notification_sender(
        state: u32,
        notification_tx: mpsc::UnboundedSender<NsmNotification>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(NsmState::with_state(state))),
            notification_tx: Some(notification_tx),
            state_repository: None,
        }
    }

    pub fn with_persistent_state_and_notification_sender(
        state: u32,
        state_repository: Arc<dyn NfsBindingRepository>,
        notification_tx: mpsc::UnboundedSender<NsmNotification>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(NsmState::with_state(state))),
            notification_tx: Some(notification_tx),
            state_repository: Some(state_repository),
        }
    }

    async fn current_state(&self) -> u32 {
        self.inner.lock().await.state
    }

    async fn monitor(
        &self,
        client_ip: IpAddr,
        mon_id: NsmMonId,
        private: [u8; SM_PRIV_SIZE],
    ) -> u32 {
        let mut state = self.inner.lock().await;
        if let Some(existing) = state
            .monitors
            .iter_mut()
            .find(|monitor| monitor.client_ip == client_ip && monitor.mon_id == mon_id)
        {
            existing.private = private;
        } else {
            state.monitors.push(NsmMonitor {
                client_ip,
                mon_id,
                private,
            });
        }
        state.state
    }

    async fn unmonitor(&self, client_ip: IpAddr, mon_id: &NsmMonId) -> u32 {
        let mut state = self.inner.lock().await;
        state
            .monitors
            .retain(|monitor| monitor.client_ip != client_ip || &monitor.mon_id != mon_id);
        state.state
    }

    async fn unmonitor_all(&self, client_ip: IpAddr, my_id: &NsmMyId) -> u32 {
        let mut state = self.inner.lock().await;
        state
            .monitors
            .retain(|monitor| monitor.client_ip != client_ip || &monitor.mon_id.my_id != my_id);
        state.state
    }

    async fn simulate_crash(&self) -> Result<(), NfsRepositoryError> {
        let next_state = if let Some(repository) = &self.state_repository {
            repository.advance_nfs_nsm_state().await?
        } else {
            let state = self.inner.lock().await;
            next_up_state(state.state)
        };

        let mut state = self.inner.lock().await;
        state.state = normalize_up_state(next_state);
        state.monitors.clear();
        Ok(())
    }

    async fn record_notification(&self, notification: NsmNotification) {
        self.inner
            .lock()
            .await
            .notifications
            .push(notification.clone());
        if let Some(notification_tx) = &self.notification_tx {
            let _ = notification_tx.send(notification);
        }
    }

    pub(crate) async fn notify_reboot_peer(&self, peer_ip: IpAddr, notify_name: &str) -> bool {
        let state = self.current_state().await;
        if !send_reboot_notification(peer_ip, notify_name, state).await {
            return false;
        }

        if let Some(repository) = &self.state_repository
            && repository.forget_nfs_nsm_peer(peer_ip).await.is_err()
        {
            return false;
        }
        true
    }
}

async fn send_reboot_notification(peer_ip: IpAddr, notify_name: &str, state: u32) -> bool {
    let rpcbind_address = SocketAddr::new(peer_ip, RPCBIND_PORT);
    let port = match lookup_port(
        rpcbind_address,
        NSM_PROGRAM,
        NSM_VERSION,
        RpcTransport::Udp,
    )
    .await
    {
        Ok(Some(port)) => port,
        Ok(None) | Err(_) => return false,
    };

    let bind_ip = if peer_ip.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let socket = match UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await {
        Ok(socket) => socket,
        Err(_) => return false,
    };

    let request = notify_rpc_call(random_xid(), notify_name, state);
    let target = SocketAddr::new(peer_ip, port);
    socket.send_to(&request, target).await.ok() == Some(request.len())
}

fn notify_rpc_call(xid: u32, notify_name: &str, state: u32) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(0);
    writer.u32(RPC_VERSION);
    writer.u32(NSM_PROGRAM);
    writer.u32(NSM_VERSION);
    writer.u32(SM_NOTIFY);
    writer.u32(AUTH_NONE);
    writer.u32(0);
    writer.u32(AUTH_NONE);
    writer.u32(0);
    writer.string(notify_name).expect("validated NSM notify name");
    writer.u32(state);
    writer.into_bytes()
}

fn random_xid() -> u32 {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    u32::from_be_bytes(bytes)
}

fn normalize_up_state(state: u32) -> u32 {
    if state == 0 {
        INITIAL_UP_STATE
    } else {
        state | 1
    }
}

fn next_up_state(state: u32) -> u32 {
    let next = state.wrapping_add(2);
    if next == 0 {
        INITIAL_UP_STATE
    } else {
        next | 1
    }
}

pub async fn serve_nsm1_stream<S>(
    stream: &mut S,
    client_ip: IpAddr,
    service: &NsmV1Service,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(request) = read_record(stream).await? {
        let response = dispatch_nsm1_rpc(service, client_ip, &request).await;
        if response.is_empty() {
            return Ok(());
        }
        write_record(stream, &response).await?;
    }
    Ok(())
}

pub async fn dispatch_nsm1_rpc(
    service: &NsmV1Service,
    client_ip: IpAddr,
    request: &[u8],
) -> Vec<u8> {
    let call = match decode_call(request) {
        Ok(call) => call,
        Err(RpcDecodeError::RpcVersion { xid, .. }) => return denied_rpc_mismatch(xid),
        Err(RpcDecodeError::NotCall { xid } | RpcDecodeError::MalformedCredential { xid }) => {
            return accepted_garbage_args(xid);
        }
        Err(RpcDecodeError::Xdr(_)) => return Vec::new(),
    };

    if call.program != NSM_PROGRAM {
        return accepted_program_unavailable(call.xid);
    }
    if call.version != NSM_VERSION {
        return accepted_program_mismatch(call.xid, NSM_VERSION, NSM_VERSION);
    }

    if std::env::var_os("NAOS_NFS_TRACE_RPC").is_some() {
        eprintln!(
            "NSM1_RPC peer={client_ip} xid={} procedure={}",
            call.xid, call.procedure
        );
    }

    match call.procedure {
        SM_NULL => empty_reply(&call),
        SM_STAT => stat_reply(service, &call).await,
        SM_MON => mon_reply(service, client_ip, &call).await,
        SM_UNMON => unmon_reply(service, client_ip, &call).await,
        SM_UNMON_ALL => unmon_all_reply(service, client_ip, &call).await,
        SM_SIMU_CRASH => simu_crash_reply(service, &call).await,
        SM_NOTIFY => notify_reply(service, client_ip, &call).await,
        _ => accepted_procedure_unavailable(call.xid),
    }
}

fn empty_reply(call: &RpcCall) -> Vec<u8> {
    if !call.body.is_empty() {
        return accepted_garbage_args(call.xid);
    }
    accepted_success(call.xid, &[])
}

async fn stat_reply(service: &NsmV1Service, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    if reader.string(SM_MAXSTRLEN).is_err() || reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    stat_result_reply(call.xid, service.current_state().await)
}

async fn mon_reply(service: &NsmV1Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let mon_id = match decode_mon_id(&mut reader) {
        Ok(mon_id) => mon_id,
        Err(()) => return accepted_garbage_args(call.xid),
    };
    let private = match reader.fixed_opaque(SM_PRIV_SIZE) {
        Ok(private) => private,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }
    let private: [u8; SM_PRIV_SIZE] = match private.try_into() {
        Ok(private) => private,
        Err(_) => return accepted_garbage_args(call.xid),
    };

    let state = service.monitor(client_ip, mon_id, private).await;
    stat_result_reply(call.xid, state)
}

async fn unmon_reply(service: &NsmV1Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let mon_id = match decode_mon_id(&mut reader) {
        Ok(mon_id) => mon_id,
        Err(()) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let state = service.unmonitor(client_ip, &mon_id).await;
    state_reply(call.xid, state)
}

async fn unmon_all_reply(service: &NsmV1Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let my_id = match decode_my_id(&mut reader) {
        Ok(my_id) => my_id,
        Err(()) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let state = service.unmonitor_all(client_ip, &my_id).await;
    state_reply(call.xid, state)
}

async fn simu_crash_reply(service: &NsmV1Service, call: &RpcCall) -> Vec<u8> {
    if !call.body.is_empty() {
        return accepted_garbage_args(call.xid);
    }
    match service.simulate_crash().await {
        Ok(()) => accepted_success(call.xid, &[]),
        Err(_) => accepted_system_error(call.xid),
    }
}

async fn notify_reply(service: &NsmV1Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let mon_name = match reader.string(SM_MAXSTRLEN) {
        Ok(mon_name) => mon_name,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let state = match reader.u32() {
        Ok(state) => state,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    service
        .record_notification(NsmNotification {
            client_ip,
            mon_name,
            state,
        })
        .await;
    accepted_success(call.xid, &[])
}

fn stat_result_reply(xid: u32, state: u32) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(STAT_SUCC);
    writer.u32(state);
    accepted_success(xid, &writer.into_bytes())
}

fn state_reply(xid: u32, state: u32) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(state);
    accepted_success(xid, &writer.into_bytes())
}

fn decode_mon_id(reader: &mut XdrReader<'_>) -> Result<NsmMonId, ()> {
    Ok(NsmMonId {
        mon_name: reader.string(SM_MAXSTRLEN).map_err(|_| ())?,
        my_id: decode_my_id(reader)?,
    })
}

fn decode_my_id(reader: &mut XdrReader<'_>) -> Result<NsmMyId, ()> {
    Ok(NsmMyId {
        name: reader.string(SM_MAXSTRLEN).map_err(|_| ())?,
        program: reader.u32().map_err(|_| ())?,
        version: reader.u32().map_err(|_| ())?,
        procedure: reader.u32().map_err(|_| ())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::XdrWriter;

    #[tokio::test]
    async fn reboot_notify_call_is_accepted_and_recorded() {
        let service = NsmV1Service::new();
        let peer_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let request = notify_rpc_call(77, "server.example", 5);

        let response = dispatch_nsm1_rpc(&service, peer_ip, &request).await;
        let mut reader = XdrReader::new(&response);
        assert_eq!(reader.u32().unwrap(), 77);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);

        let state = service.inner.lock().await;
        assert_eq!(
            state.notifications,
            vec![NsmNotification {
                client_ip: peer_ip,
                mon_name: "server.example".to_owned(),
                state: 5,
            }]
        );
    }

    #[tokio::test]
    async fn configured_state_is_normalized_and_reported() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let service = NsmV1Service::with_state_and_notification_sender(2, tx);
        assert_eq!(service.current_state().await, 3);
    }

    #[tokio::test]
    async fn stat_returns_success_and_current_odd_state() {
        let service = NsmV1Service::new();
        let mut body = XdrWriter::new();
        body.string("client.example").unwrap();
        let call = rpc_call(31, SM_STAT, &body.into_bytes());

        let reply = dispatch_nsm1_rpc(&service, "127.0.0.1".parse().unwrap(), &call).await;
        let mut reader = XdrReader::new(&reply);
        assert_rpc_success_prefix(&mut reader, 31);
        assert_eq!(reader.u32().unwrap(), STAT_SUCC);
        assert_eq!(reader.u32().unwrap(), INITIAL_UP_STATE);
        reader.finish().unwrap();
    }

    #[tokio::test]
    async fn mon_is_idempotent_and_refreshes_private_cookie() {
        let service = NsmV1Service::new();
        let client_ip = "192.0.2.10".parse().unwrap();

        for private in [[7; SM_PRIV_SIZE], [8; SM_PRIV_SIZE]] {
            let body = mon_body("server.example", "client.example", private);
            let call = rpc_call(32, SM_MON, &body);
            let reply = dispatch_nsm1_rpc(&service, client_ip, &call).await;
            let mut reader = XdrReader::new(&reply);
            assert_rpc_success_prefix(&mut reader, 32);
            assert_eq!(reader.u32().unwrap(), STAT_SUCC);
            assert_eq!(reader.u32().unwrap(), INITIAL_UP_STATE);
            reader.finish().unwrap();
        }

        let state = service.inner.lock().await;
        assert_eq!(state.monitors.len(), 1);
        assert_eq!(state.monitors[0].client_ip, client_ip);
        assert_eq!(state.monitors[0].mon_id.mon_name, "server.example");
        assert_eq!(state.monitors[0].private, [8; SM_PRIV_SIZE]);
    }

    #[tokio::test]
    async fn unmon_and_unmon_all_remove_matching_monitors() {
        let service = NsmV1Service::new();
        let client_ip = "192.0.2.10".parse().unwrap();
        let other_ip = "192.0.2.11".parse().unwrap();

        for (ip, mon_name) in [
            (client_ip, "server-a.example"),
            (client_ip, "server-b.example"),
            (other_ip, "server-a.example"),
        ] {
            let call = rpc_call(
                40,
                SM_MON,
                &mon_body(mon_name, "client.example", [7; SM_PRIV_SIZE]),
            );
            dispatch_nsm1_rpc(&service, ip, &call).await;
        }
        assert_eq!(service.inner.lock().await.monitors.len(), 3);

        let call = rpc_call(
            41,
            SM_UNMON,
            &mon_id_body("server-a.example", "client.example"),
        );
        dispatch_nsm1_rpc(&service, client_ip, &call).await;
        {
            let state = service.inner.lock().await;
            assert_eq!(state.monitors.len(), 2);
            assert!(state.monitors.iter().any(|monitor| {
                monitor.client_ip == other_ip && monitor.mon_id.mon_name == "server-a.example"
            }));
        }

        let call = rpc_call(42, SM_UNMON_ALL, &my_id_body("client.example"));
        dispatch_nsm1_rpc(&service, client_ip, &call).await;
        let state = service.inner.lock().await;
        assert_eq!(state.monitors.len(), 1);
        assert_eq!(state.monitors[0].client_ip, other_ip);
    }

    #[tokio::test]
    async fn simu_crash_advances_odd_state_and_clears_monitors() {
        let service = NsmV1Service::new();
        let client_ip = "192.0.2.10".parse().unwrap();
        let call = rpc_call(
            50,
            SM_MON,
            &mon_body("server.example", "client.example", [7; SM_PRIV_SIZE]),
        );
        dispatch_nsm1_rpc(&service, client_ip, &call).await;
        assert_eq!(service.inner.lock().await.monitors.len(), 1);

        let call = rpc_call(51, SM_SIMU_CRASH, &[]);
        let reply = dispatch_nsm1_rpc(&service, client_ip, &call).await;
        let mut reader = XdrReader::new(&reply);
        assert_rpc_success_prefix(&mut reader, 51);
        reader.finish().unwrap();

        let state = service.inner.lock().await;
        assert_eq!(state.state, 3);
        assert_eq!(state.state % 2, 1);
        assert!(state.monitors.is_empty());
    }

    #[tokio::test]
    async fn notify_records_peer_state_change() {
        let (notification_tx, mut notification_rx) = mpsc::unbounded_channel();
        let service = NsmV1Service::with_notification_sender(notification_tx);
        let client_ip = "192.0.2.20".parse().unwrap();
        let mut body = XdrWriter::new();
        body.string("peer.example").unwrap();
        body.u32(9);
        let call = rpc_call(60, SM_NOTIFY, &body.into_bytes());

        let reply = dispatch_nsm1_rpc(&service, client_ip, &call).await;
        let mut reader = XdrReader::new(&reply);
        assert_rpc_success_prefix(&mut reader, 60);
        reader.finish().unwrap();

        let expected = NsmNotification {
            client_ip,
            mon_name: "peer.example".to_owned(),
            state: 9,
        };
        let state = service.inner.lock().await;
        assert_eq!(state.notifications, vec![expected.clone()]);
        drop(state);
        assert_eq!(notification_rx.recv().await, Some(expected));
    }

    #[tokio::test]
    async fn malformed_mon_is_rejected_as_garbage_args() {
        let service = NsmV1Service::new();
        let mut body = XdrWriter::new();
        body.string("server.example").unwrap();
        let call = rpc_call(33, SM_MON, &body.into_bytes());

        let reply = dispatch_nsm1_rpc(&service, "127.0.0.1".parse().unwrap(), &call).await;
        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 33);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 4);
    }

    fn mon_body(mon_name: &str, my_name: &str, private: [u8; SM_PRIV_SIZE]) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.string(mon_name).unwrap();
        encode_my_id(&mut writer, my_name);
        writer.fixed_opaque(&private);
        writer.into_bytes()
    }

    fn mon_id_body(mon_name: &str, my_name: &str) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.string(mon_name).unwrap();
        encode_my_id(&mut writer, my_name);
        writer.into_bytes()
    }

    fn my_id_body(my_name: &str) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        encode_my_id(&mut writer, my_name);
        writer.into_bytes()
    }

    fn encode_my_id(writer: &mut XdrWriter, my_name: &str) {
        writer.string(my_name).unwrap();
        writer.u32(100021);
        writer.u32(4);
        writer.u32(16);
    }

    fn rpc_call(xid: u32, procedure: u32, body: &[u8]) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(RPC_VERSION);
        writer.u32(NSM_PROGRAM);
        writer.u32(NSM_VERSION);
        writer.u32(procedure);
        writer.u32(AUTH_NONE);
        writer.opaque(&[]).unwrap();
        writer.u32(AUTH_NONE);
        writer.opaque(&[]).unwrap();
        let mut bytes = writer.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    fn assert_rpc_success_prefix(reader: &mut XdrReader<'_>, xid: u32) {
        assert_eq!(reader.u32().unwrap(), xid);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 0);
    }
}
