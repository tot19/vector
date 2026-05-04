use bytes::Bytes;
use chrono::Utc;
use listenfd::ListenFd;
use std::path::PathBuf;
use vector_lib::{
    EstimatedJsonEncodedSizeOf,
    config::{LegacyKey, LogNamespace, log_schema},
    configurable::configurable_component,
    internal_event::{ByteSize, BytesReceived, InternalEventHandle as _, Protocol},
    lookup::{OwnedValuePath, lookup_v2::OptionalValuePath, owned_value_path, path},
};
use vrl::value::{Kind, kind::Collection};

use crate::{
    SourceSender,
    config::{DataType, GenerateConfig, Resource, SourceConfig, SourceContext, SourceOutput},
    event::Event,
    internal_events::{
        SocketBindError, SocketBytesSent, SocketEventsReceived, SocketMode, SocketReceiveError,
        SocketSendError, StreamClosedError,
    },
    net,
    shutdown::ShutdownSignal,
    sources::util::net::{SocketListenAddr, try_bind_udp_socket},
};

mod mib;
mod parser;

use mib::MibResolver;
use parser::{MAX_SNMP_MESSAGE_SIZE, parse_snmp_trap};

/// Configuration for the `snmp_trap` source.
#[configurable_component(source("snmp_trap", "Receive SNMP traps over UDP."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct SnmpTrapConfig {
    /// The address to listen for SNMP traps on.
    ///
    /// SNMP traps are typically sent to UDP port 162.
    #[configurable(metadata(docs::examples = "0.0.0.0:162"))]
    #[configurable(metadata(docs::examples = "127.0.0.1:1162"))]
    address: SocketListenAddr,

    /// The size of the receive buffer used for the listening socket.
    ///
    /// This should not typically need to be changed.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    receive_buffer_bytes: Option<usize>,

    /// Overrides the name of the log field used to add the peer host to each event.
    ///
    /// The value is the peer host's IP address. For example, `192.168.1.1`.
    ///
    /// By default, the [global `log_schema.host_key` option][global_host_key] is used.
    ///
    /// Set to `""` to suppress this key.
    ///
    /// [global_host_key]: https://vector.dev/docs/reference/configuration/global-options/#log_schema.host_key
    host_key: Option<OptionalValuePath>,

    /// MIB files or directories to load for OID name resolution.
    ///
    /// Directories are scanned recursively with bounded depth and file count, without following
    /// symlinked directories. Directory scans load files with common MIB extensions or no
    /// extension, and each MIB file must be at most 8 MiB. Numeric OIDs are always preserved, and
    /// resolved names are added in separate metadata fields.
    #[serde(default)]
    mib_paths: Vec<PathBuf>,

    /// The namespace to use for logs. This overrides the global setting.
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    log_namespace: Option<bool>,
}

impl SnmpTrapConfig {
    fn host_key(&self) -> Option<OwnedValuePath> {
        match &self.host_key {
            Some(host_key) => host_key.clone().path,
            None => log_schema().host_key().cloned(),
        }
    }

    fn schema_definition(&self, log_namespace: LogNamespace) -> vector_lib::schema::Definition {
        let varbind_kind = Kind::array(
            Collection::empty().with_unknown(Kind::object(
                Collection::empty()
                    .with_known("oid", Kind::bytes())
                    .with_known("oid_name", Kind::bytes().or_undefined())
                    .with_known("oid_module", Kind::bytes().or_undefined())
                    .with_known("oid_symbol", Kind::bytes().or_undefined())
                    .with_known("oid_instance", Kind::bytes().or_undefined())
                    .with_known("type", Kind::bytes())
                    .with_known("value", Kind::bytes())
                    .with_known("value_bytes_hex", Kind::bytes().or_undefined())
                    .with_known("value_oid_name", Kind::bytes().or_undefined())
                    .with_known("value_oid_module", Kind::bytes().or_undefined())
                    .with_known("value_oid_symbol", Kind::bytes().or_undefined())
                    .with_known("value_oid_instance", Kind::bytes().or_undefined()),
            )),
        );

        vector_lib::schema::Definition::new_with_default_metadata(
            Kind::object(Collection::empty()),
            [log_namespace],
        )
        .with_event_field(&owned_value_path!("snmp_version"), Kind::bytes(), None)
        .with_event_field(&owned_value_path!("pdu_type"), Kind::bytes(), None)
        .with_event_field(&owned_value_path!("source_address"), Kind::bytes(), None)
        .with_event_field(&owned_value_path!("community"), Kind::bytes(), None)
        .with_event_field(
            &owned_value_path!("enterprise_oid"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("enterprise_oid_name"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("enterprise_oid_module"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("enterprise_oid_symbol"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("enterprise_oid_instance"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("agent_address"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("generic_trap"),
            Kind::integer().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("generic_trap_name"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("specific_trap"),
            Kind::integer().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("request_id"),
            Kind::integer().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("trap_oid"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("trap_oid_name"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("trap_oid_module"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("trap_oid_symbol"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("trap_oid_instance"),
            Kind::bytes().or_undefined(),
            None,
        )
        .with_event_field(
            &owned_value_path!("uptime"),
            Kind::integer().or_undefined(),
            None,
        )
        .with_event_field(&owned_value_path!("varbinds"), varbind_kind, None)
        .with_event_field(
            &owned_value_path!("message"),
            Kind::bytes(),
            Some("message"),
        )
        .with_standard_vector_source_metadata()
        .with_source_metadata(
            Self::NAME,
            self.host_key().map(LegacyKey::InsertIfEmpty),
            &owned_value_path!("host"),
            Kind::bytes(),
            Some("host"),
        )
    }
}

impl Default for SnmpTrapConfig {
    fn default() -> Self {
        Self {
            address: SocketListenAddr::SocketAddr("0.0.0.0:162".parse().unwrap()),
            receive_buffer_bytes: None,
            host_key: None,
            mib_paths: Vec::new(),
            log_namespace: None,
        }
    }
}

impl GenerateConfig for SnmpTrapConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self::default()).unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "snmp_trap")]
impl SourceConfig for SnmpTrapConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<super::Source> {
        let log_namespace = cx.log_namespace(self.log_namespace);
        let host_key = self.host_key();
        let mib_resolver = MibResolver::from_paths(&self.mib_paths)?;

        Ok(Box::pin(snmp_trap_udp(
            self.address,
            self.receive_buffer_bytes,
            host_key,
            mib_resolver,
            cx.shutdown,
            log_namespace,
            cx.out,
        )))
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let log_namespace = global_log_namespace.merge(self.log_namespace);
        let schema_definition = self.schema_definition(log_namespace);

        vec![SourceOutput::new_maybe_logs(
            DataType::Log,
            schema_definition,
        )]
    }

    fn resources(&self) -> Vec<Resource> {
        vec![self.address.as_udp_resource()]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}

async fn snmp_trap_udp(
    address: SocketListenAddr,
    receive_buffer_bytes: Option<usize>,
    host_key: Option<OwnedValuePath>,
    mib_resolver: MibResolver,
    shutdown: ShutdownSignal,
    log_namespace: LogNamespace,
    mut out: SourceSender,
) -> Result<(), ()> {
    let mut shutdown = shutdown;
    let listenfd = ListenFd::from_env();
    let socket = try_bind_udp_socket(address, listenfd)
        .await
        .map_err(|error| {
            emit!(SocketBindError {
                mode: SocketMode::Udp,
                error: &error,
            })
        })?;

    if let Some(receive_buffer_bytes) = receive_buffer_bytes
        && let Err(error) = net::set_receive_buffer_size(&socket, receive_buffer_bytes)
    {
        warn!(message = "Failed configuring receive buffer size on UDP socket.", %error);
    }

    info!(
        message = "Listening for SNMP traps.",
        addr = %address,
        r#type = "udp"
    );

    let bytes_received = register!(BytesReceived::from(Protocol::UDP));
    let mut buf = vec![0; MAX_SNMP_MESSAGE_SIZE];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                let (byte_size, peer_addr) = match result {
                    Ok(result) => result,
                    Err(error) => {
                        emit!(SocketReceiveError {
                            mode: SocketMode::Udp,
                            error: &error,
                        });
                        continue;
                    }
                };

                bytes_received.emit(ByteSize(byte_size));
                let data = Bytes::copy_from_slice(&buf[..byte_size]);

                match parse_snmp_trap(&data, peer_addr, &mib_resolver) {
                    Ok(mut notification) => {
                        let count = notification.events.len();
                        emit!(SocketEventsReceived {
                            mode: SocketMode::Udp,
                            byte_size: notification.events.estimated_json_encoded_size_of(),
                            count,
                        });

                        enrich_events(&mut notification.events, &host_key, peer_addr, log_namespace);

                        tokio::select! {
                            result = out.send_batch(notification.events) => {
                                if result.is_err() {
                                    emit!(StreamClosedError { count });
                                    return Ok(());
                                }
                            }
                            _ = &mut shutdown => return Ok(()),
                        }

                        if let Some(response) = notification.response.take() {
                            tokio::select! {
                                result = socket.send_to(&response, peer_addr) => {
                                    match result {
                                        Ok(byte_size) => {
                                            emit!(SocketBytesSent {
                                                mode: SocketMode::Udp,
                                                byte_size,
                                            });
                                        }
                                        Err(error) => {
                                            emit!(SocketSendError {
                                                mode: SocketMode::Udp,
                                                error: &error,
                                            });
                                        }
                                    }
                                }
                                _ = &mut shutdown => return Ok(()),
                            }
                        }
                    }
                    Err(error) => {
                        emit!(crate::internal_events::SnmpTrapParseError {
                            error: error.to_string(),
                            error_code: error.error_code(),
                        });
                    }
                }
            }
            _ = &mut shutdown => return Ok(()),
        }
    }
}

fn enrich_events(
    events: &mut [Event],
    host_key: &Option<OwnedValuePath>,
    peer_addr: std::net::SocketAddr,
    log_namespace: LogNamespace,
) {
    for event in events {
        let Event::Log(log) = event else {
            continue;
        };

        log_namespace.insert_standard_vector_source_metadata(log, SnmpTrapConfig::NAME, Utc::now());
        log_namespace.insert_source_metadata(
            SnmpTrapConfig::NAME,
            log,
            host_key.as_ref().map(LegacyKey::InsertIfEmpty),
            path!("host"),
            peer_addr.ip().to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use snmp_parser::snmp::{PduType, SnmpPdu};
    use tokio::{
        net::UdpSocket,
        time::{Duration, Instant, sleep, timeout},
    };
    use vector_lib::event::LogEvent;

    use crate::{
        config::ComponentKey,
        test_util::{
            addr::next_addr,
            components::{SOCKET_PUSH_SOURCE_TAGS, assert_source_compliance},
        },
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<SnmpTrapConfig>();
    }

    #[tokio::test]
    async fn test_udp_socket_bind() {
        let (_guard, addr) = next_addr();
        let config = SnmpTrapConfig {
            address: SocketListenAddr::SocketAddr(addr),
            receive_buffer_bytes: None,
            host_key: None,
            mib_paths: Vec::new(),
            log_namespace: None,
        };

        let (tx, _rx) = SourceSender::new_test();
        // This should successfully bind
        let source = SourceConfig::build(&config, SourceContext::new_test(tx, None))
            .await
            .expect("Failed to build source");

        // Just verify we can create the source
        drop(source);
    }

    #[tokio::test]
    async fn test_config_default() {
        let config = SnmpTrapConfig::default();
        assert_eq!(
            config.address,
            SocketListenAddr::SocketAddr("0.0.0.0:162".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn test_config_with_options() {
        let (_guard, addr) = next_addr();
        let mut host_path = vector_lib::lookup::OwnedValuePath::root();
        host_path.push_field("host");
        let config = SnmpTrapConfig {
            address: SocketListenAddr::SocketAddr(addr),
            receive_buffer_bytes: Some(65536),
            host_key: Some(OptionalValuePath::from(host_path)),
            mib_paths: Vec::new(),
            log_namespace: None,
        };

        let (tx, _rx) = SourceSender::new_test();
        let source = SourceConfig::build(&config, SourceContext::new_test(tx, None))
            .await
            .expect("Failed to build source with options");

        drop(source);
    }

    #[tokio::test]
    async fn test_config_rejects_missing_mib_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = SnmpTrapConfig {
            address: SocketListenAddr::SocketAddr("127.0.0.1:0".parse().unwrap()),
            receive_buffer_bytes: None,
            host_key: None,
            mib_paths: vec![temp_dir.path().join("missing")],
            log_namespace: None,
        };

        let (tx, _rx) = SourceSender::new_test();
        let error = match SourceConfig::build(&config, SourceContext::new_test(tx, None)).await {
            Ok(_) => panic!("expected missing MIB path to fail source build"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("Failed to read MIB path"));
    }

    #[tokio::test]
    async fn test_udp_source_receives_trap_with_metadata() {
        assert_source_compliance(&SOCKET_PUSH_SOURCE_TAGS, async move {
            let (_guard, addr) = next_addr();
            let config = SnmpTrapConfig {
                address: SocketListenAddr::SocketAddr(addr),
                receive_buffer_bytes: None,
                host_key: None,
                mib_paths: Vec::new(),
                log_namespace: None,
            };

            let key = ComponentKey::from("snmp_trap");
            let (tx, mut rx) = SourceSender::new_test();
            let (context, shutdown) = SourceContext::new_shutdown(&key, tx);
            let shutdown_complete = shutdown.shutdown_tripwire();

            let source = config.build(context).await.unwrap();
            tokio::spawn(source);
            sleep(Duration::from_millis(150)).await;

            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket
                .send_to(&v2c_notification(PduType::TrapV2), addr)
                .await
                .unwrap();

            let event = timeout(Duration::from_secs(2), rx.next())
                .await
                .unwrap()
                .unwrap();
            let log = event.as_log();

            assert_eq!(log["snmp_version"], "2c".into());
            assert_eq!(log["pdu_type"], "trap_v2".into());
            assert_eq!(log["source_type"], "snmp_trap".into());
            assert_eq!(log["host"], "127.0.0.1".into());

            shutdown
                .shutdown_all(Some(Instant::now() + Duration::from_millis(100)))
                .await;
            shutdown_complete.await;
        })
        .await;
    }

    #[tokio::test]
    async fn test_udp_source_uses_custom_host_key() {
        let (_guard, addr) = next_addr();
        let mut host_path = vector_lib::lookup::OwnedValuePath::root();
        host_path.push_field("agent_host");
        let config = SnmpTrapConfig {
            address: SocketListenAddr::SocketAddr(addr),
            receive_buffer_bytes: None,
            host_key: Some(OptionalValuePath::from(host_path)),
            mib_paths: Vec::new(),
            log_namespace: None,
        };

        let key = ComponentKey::from("snmp_trap");
        let (tx, mut rx) = SourceSender::new_test();
        let (context, shutdown) = SourceContext::new_shutdown(&key, tx);
        let shutdown_complete = shutdown.shutdown_tripwire();

        let source = config.build(context).await.unwrap();
        tokio::spawn(source);
        sleep(Duration::from_millis(150)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&v2c_notification(PduType::TrapV2), addr)
            .await
            .unwrap();

        let event = timeout(Duration::from_secs(2), rx.next())
            .await
            .unwrap()
            .unwrap();
        let log = event.as_log();

        assert_eq!(log["agent_host"], "127.0.0.1".into());
        assert!(log.get("host").is_none());

        shutdown
            .shutdown_all(Some(Instant::now() + Duration::from_millis(100)))
            .await;
        shutdown_complete.await;
    }

    #[tokio::test]
    async fn test_udp_source_can_disable_host_key() {
        let (_guard, addr) = next_addr();
        let config = SnmpTrapConfig {
            address: SocketListenAddr::SocketAddr(addr),
            receive_buffer_bytes: None,
            host_key: Some(OptionalValuePath::none()),
            mib_paths: Vec::new(),
            log_namespace: None,
        };

        let key = ComponentKey::from("snmp_trap");
        let (tx, mut rx) = SourceSender::new_test();
        let (context, shutdown) = SourceContext::new_shutdown(&key, tx);
        let shutdown_complete = shutdown.shutdown_tripwire();

        let source = config.build(context).await.unwrap();
        tokio::spawn(source);
        sleep(Duration::from_millis(150)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&v2c_notification(PduType::TrapV2), addr)
            .await
            .unwrap();

        let event = timeout(Duration::from_secs(2), rx.next())
            .await
            .unwrap()
            .unwrap();
        let log = event.as_log();

        assert!(log.get("host").is_none());

        shutdown
            .shutdown_all(Some(Instant::now() + Duration::from_millis(100)))
            .await;
        shutdown_complete.await;
    }

    #[tokio::test]
    async fn test_udp_source_acknowledges_inform_request() {
        let (_guard, addr) = next_addr();
        let config = SnmpTrapConfig {
            address: SocketListenAddr::SocketAddr(addr),
            receive_buffer_bytes: None,
            host_key: None,
            mib_paths: Vec::new(),
            log_namespace: None,
        };

        let key = ComponentKey::from("snmp_trap");
        let (tx, mut rx) = SourceSender::new_test();
        let (context, shutdown) = SourceContext::new_shutdown(&key, tx);
        let shutdown_complete = shutdown.shutdown_tripwire();

        let source = config.build(context).await.unwrap();
        tokio::spawn(source);
        sleep(Duration::from_millis(150)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(addr).await.unwrap();
        socket
            .send(&v2c_notification(PduType::InformRequest))
            .await
            .unwrap();

        let mut response = vec![0; MAX_SNMP_MESSAGE_SIZE];
        let response_len = timeout(Duration::from_secs(2), socket.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        let (_, response) = snmp_parser::parse_snmp_v2c(&response[..response_len]).unwrap();
        match response.pdu {
            SnmpPdu::Generic(pdu) => {
                assert_eq!(pdu.pdu_type, PduType::Response);
                assert_eq!(pdu.req_id, 42);
                assert_eq!(pdu.err_index, 0);
                assert_eq!(pdu.var.len(), 3);
            }
            other => panic!("expected response PDU, got {other:?}"),
        }

        let event = timeout(Duration::from_secs(2), rx.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.as_log()["pdu_type"], "inform_request".into());

        shutdown
            .shutdown_all(Some(Instant::now() + Duration::from_millis(100)))
            .await;
        shutdown_complete.await;
    }

    #[tokio::test]
    async fn test_udp_source_does_not_ack_when_downstream_is_closed() {
        let (_guard, addr) = next_addr();
        let config = SnmpTrapConfig {
            address: SocketListenAddr::SocketAddr(addr),
            receive_buffer_bytes: None,
            host_key: None,
            mib_paths: Vec::new(),
            log_namespace: None,
        };

        let key = ComponentKey::from("snmp_trap");
        let (tx, rx) = SourceSender::new_test();
        drop(rx);
        let (context, _shutdown) = SourceContext::new_shutdown(&key, tx);

        let source = config.build(context).await.unwrap();
        let source = tokio::spawn(source);
        sleep(Duration::from_millis(150)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(addr).await.unwrap();
        socket
            .send(&v2c_notification(PduType::InformRequest))
            .await
            .unwrap();

        timeout(Duration::from_secs(2), source)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let mut response = vec![0; MAX_SNMP_MESSAGE_SIZE];
        assert!(
            timeout(Duration::from_millis(300), socket.recv(&mut response))
                .await
                .is_err(),
            "inform should not be acknowledged when Vector cannot forward the event"
        );
    }

    #[tokio::test]
    async fn test_udp_source_shutdown_interrupts_downstream_backpressure() {
        let (_guard, addr) = next_addr();
        let config = SnmpTrapConfig {
            address: SocketListenAddr::SocketAddr(addr),
            receive_buffer_bytes: None,
            host_key: None,
            mib_paths: Vec::new(),
            log_namespace: None,
        };

        let key = ComponentKey::from("snmp_trap");
        let (mut tx, _rx) = SourceSender::new_test_sender_with_options(1, None);
        tx.send_batch(vec![Event::Log(LogEvent::default())])
            .await
            .unwrap();
        let (context, shutdown) = SourceContext::new_shutdown(&key, tx);
        let shutdown_complete = shutdown.shutdown_tripwire();

        let source = config.build(context).await.unwrap();
        let source = tokio::spawn(source);
        sleep(Duration::from_millis(150)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&v2c_notification(PduType::TrapV2), addr)
            .await
            .unwrap();
        sleep(Duration::from_millis(150)).await;

        shutdown
            .shutdown_all(Some(Instant::now() + Duration::from_millis(100)))
            .await;
        timeout(Duration::from_secs(2), shutdown_complete)
            .await
            .unwrap();
        timeout(Duration::from_secs(2), source)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_udp_source_rejects_malformed_inform_request_without_ack() {
        let (_guard, addr) = next_addr();
        let config = SnmpTrapConfig {
            address: SocketListenAddr::SocketAddr(addr),
            receive_buffer_bytes: None,
            host_key: None,
            mib_paths: Vec::new(),
            log_namespace: None,
        };

        let key = ComponentKey::from("snmp_trap");
        let (tx, mut rx) = SourceSender::new_test();
        let (context, shutdown) = SourceContext::new_shutdown(&key, tx);
        let shutdown_complete = shutdown.shutdown_tripwire();

        let source = config.build(context).await.unwrap();
        tokio::spawn(source);
        sleep(Duration::from_millis(150)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(addr).await.unwrap();
        socket
            .send(&v2c_message(
                PduType::InformRequest,
                42,
                vec![varbind(
                    &[1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 0],
                    encode_integer(7),
                )],
            ))
            .await
            .unwrap();

        let mut response = vec![0; MAX_SNMP_MESSAGE_SIZE];
        assert!(
            timeout(Duration::from_millis(300), socket.recv(&mut response))
                .await
                .is_err(),
            "malformed inform should not receive an RFC 3416 Response-PDU"
        );
        assert!(
            timeout(Duration::from_millis(300), rx.next())
                .await
                .is_err(),
            "malformed inform should not produce an event"
        );

        shutdown
            .shutdown_all(Some(Instant::now() + Duration::from_millis(100)))
            .await;
        shutdown_complete.await;
    }

    #[tokio::test]
    async fn test_udp_source_resolves_mib_oids() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mib_path = temp_dir.path().join("TEST-MIB.txt");
        std::fs::write(&mib_path, TEST_MIB).unwrap();

        let (_guard, addr) = next_addr();
        let config = SnmpTrapConfig {
            address: SocketListenAddr::SocketAddr(addr),
            receive_buffer_bytes: None,
            host_key: None,
            mib_paths: vec![temp_dir.path().to_path_buf()],
            log_namespace: None,
        };

        let key = ComponentKey::from("snmp_trap");
        let (tx, mut rx) = SourceSender::new_test();
        let (context, shutdown) = SourceContext::new_shutdown(&key, tx);
        let shutdown_complete = shutdown.shutdown_tripwire();

        let source = config.build(context).await.unwrap();
        tokio::spawn(source);
        sleep(Duration::from_millis(150)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&v2c_notification(PduType::TrapV2), addr)
            .await
            .unwrap();

        let event = timeout(Duration::from_secs(2), rx.next())
            .await
            .unwrap()
            .unwrap();
        let log = event.as_log();
        assert_eq!(log["trap_oid_name"], "TEST-MIB::testTrap".into());
        assert_eq!(log["trap_oid_module"], "TEST-MIB".into());
        assert_eq!(log["trap_oid_symbol"], "testTrap".into());

        let varbinds = log["varbinds"].as_array().unwrap();
        assert_eq!(
            varbinds[1].get("value_oid_name").unwrap(),
            &"TEST-MIB::testTrap".into()
        );
        assert_eq!(
            varbinds[2].get("oid_name").unwrap(),
            &"TEST-MIB::testValue.0".into()
        );
        assert_eq!(varbinds[2].get("oid_instance").unwrap(), &"0".into());

        shutdown
            .shutdown_all(Some(Instant::now() + Duration::from_millis(100)))
            .await;
        shutdown_complete.await;
    }

    fn v2c_notification(pdu_type: PduType) -> Vec<u8> {
        v2c_message(
            pdu_type,
            42,
            vec![
                varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], timeticks(123_456)),
                varbind(
                    &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0],
                    oid_value(&[1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1]),
                ),
                varbind(&[1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 0], encode_integer(7)),
            ],
        )
    }

    const TEST_MIB: &str = r#"
TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    enterprises, OBJECT-TYPE, NOTIFICATION-TYPE
        FROM SNMPv2-SMI;

testRoot OBJECT IDENTIFIER ::= { enterprises 8072 }
testNotifications OBJECT IDENTIFIER ::= { testRoot 2 }
testNotificationPrefix OBJECT IDENTIFIER ::= { testNotifications 3 }
testSpecificNotifications OBJECT IDENTIFIER ::= { testNotificationPrefix 0 }

testTrap NOTIFICATION-TYPE
    OBJECTS { testValue }
    STATUS current
    DESCRIPTION "A test notification."
    ::= { testSpecificNotifications 1 }

testObjects OBJECT IDENTIFIER ::= { testNotifications 4 }
testValue OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A test value."
    ::= { testObjects 1 }

END
"#;

    fn v2c_message(pdu_type: PduType, request_id: u32, varbinds: Vec<Vec<u8>>) -> Vec<u8> {
        let mut varbind_list = Vec::new();
        for varbind in varbinds {
            varbind_list.extend(varbind);
        }

        let mut pdu = Vec::new();
        pdu.extend(encode_integer(request_id as u64));
        pdu.extend(encode_integer(0));
        pdu.extend(encode_integer(0));
        pdu.extend(encode_sequence(&varbind_list));

        let mut message = Vec::new();
        message.extend(encode_integer(1));
        message.extend(encode_tlv(0x04, b"public"));
        message.extend(encode_tlv(0xa0 | pdu_type.0 as u8, &pdu));

        encode_sequence(&message)
    }

    fn varbind(oid_arcs: &[u64], value: Vec<u8>) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend(oid_value(oid_arcs));
        content.extend(value);
        encode_sequence(&content)
    }

    fn oid_value(arcs: &[u64]) -> Vec<u8> {
        encode_tlv(0x06, &oid(arcs))
    }

    fn timeticks(value: u64) -> Vec<u8> {
        encode_tlv(0x43, &unsigned_integer_content(value))
    }

    fn oid(arcs: &[u64]) -> Vec<u8> {
        assert!(arcs.len() >= 2);
        let mut encoded = vec![(arcs[0] * 40 + arcs[1]) as u8];
        for mut arc in arcs.iter().copied().skip(2) {
            let mut stack = vec![(arc & 0x7f) as u8];
            arc >>= 7;
            while arc > 0 {
                stack.push(((arc & 0x7f) as u8) | 0x80);
                arc >>= 7;
            }
            encoded.extend(stack.into_iter().rev());
        }
        encoded
    }

    fn encode_sequence(content: &[u8]) -> Vec<u8> {
        encode_tlv(0x30, content)
    }

    fn encode_integer(value: u64) -> Vec<u8> {
        encode_tlv(0x02, &unsigned_integer_content(value))
    }

    fn unsigned_integer_content(value: u64) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let first_non_zero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let mut content = bytes[first_non_zero..].to_vec();
        if content[0] & 0x80 != 0 {
            content.insert(0, 0);
        }
        content
    }

    fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut value = Vec::with_capacity(1 + 5 + content.len());
        value.push(tag);
        if content.len() < 128 {
            value.push(content.len() as u8);
        } else {
            let bytes = content.len().to_be_bytes();
            let first_non_zero = bytes
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(bytes.len() - 1);
            let significant = &bytes[first_non_zero..];
            value.push(0x80 | significant.len() as u8);
            value.extend(significant);
        }
        value.extend(content);
        value
    }
}

#[cfg(all(test, feature = "snmp-trap-integration-tests"))]
mod integration_tests;
