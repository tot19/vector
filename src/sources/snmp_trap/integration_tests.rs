#![cfg(feature = "snmp-trap-integration-tests")]

use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Output},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::{Stream, StreamExt};
use tokio::{task::JoinHandle, time::Instant};
use vector_lib::event::{Event, LogEvent, Value};

use super::SnmpTrapConfig;
use crate::{
    SourceSender,
    config::{ComponentKey, SourceConfig, SourceContext},
    shutdown::SourceShutdownCoordinator,
    sources::util::net::SocketListenAddr,
    test_util::addr::next_addr,
};

const ENTERPRISE_OID: &str = ".1.3.6.1.4.1.8072.9999";
const TRAP_OID: &str = ".1.3.6.1.4.1.8072.9999.0.1";
const VALUE_OID: &str = ".1.3.6.1.4.1.8072.9999.1.1.0";
const TEXT_OID: &str = ".1.3.6.1.4.1.8072.9999.1.2.0";
const BYTES_OID: &str = ".1.3.6.1.4.1.8072.9999.1.3.0";
const UNSIGNED_OID: &str = ".1.3.6.1.4.1.8072.9999.1.4.0";
const COUNTER_OID: &str = ".1.3.6.1.4.1.8072.9999.1.5.0";
const TIMETICKS_OID: &str = ".1.3.6.1.4.1.8072.9999.1.6.0";
const IP_ADDRESS_OID: &str = ".1.3.6.1.4.1.8072.9999.1.7.0";
const OBJECT_ID_OID: &str = ".1.3.6.1.4.1.8072.9999.1.8.0";
const NULL_OID: &str = ".1.3.6.1.4.1.8072.9999.1.9.0";
const DECIMAL_BYTES_OID: &str = ".1.3.6.1.4.1.8072.9999.1.10.0";

const TRAP_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.0.1";
const VALUE_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.1.1.0";
const TEXT_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.1.2.0";
const BYTES_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.1.3.0";
const UNSIGNED_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.1.4.0";
const COUNTER_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.1.5.0";
const TIMETICKS_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.1.6.0";
const IP_ADDRESS_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.1.7.0";
const OBJECT_ID_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.1.8.0";
const NULL_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.1.9.0";
const DECIMAL_BYTES_OID_NO_DOT: &str = "1.3.6.1.4.1.8072.9999.1.10.0";

type EventStream = Box<dyn Stream<Item = Event> + Unpin>;

struct RunningSource {
    address: SocketAddr,
    events: EventStream,
    shutdown: SourceShutdownCoordinator,
    task: JoinHandle<Result<(), ()>>,
}

impl RunningSource {
    async fn stop(self) {
        self.shutdown
            .shutdown_all(Some(Instant::now() + Duration::from_millis(250)))
            .await;

        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .expect("SNMP trap source should stop before timeout")
            .expect("SNMP trap source task should not panic")
            .expect("SNMP trap source should stop cleanly");
    }
}

async fn start_source() -> RunningSource {
    let (_guard, address) = next_addr();
    let config = SnmpTrapConfig {
        address: SocketListenAddr::SocketAddr(address),
        receive_buffer_bytes: None,
        host_key: None,
        mib_paths: vec![test_mib_path()],
        log_namespace: None,
    };

    let key = ComponentKey::from("snmp_trap_net_snmp_integration");
    let (tx, events) = SourceSender::new_test();
    let (context, shutdown) = SourceContext::new_shutdown(&key, tx);
    let source = config.build(context).await.unwrap();
    let task = tokio::spawn(source);

    tokio::time::sleep(Duration::from_millis(150)).await;

    RunningSource {
        address,
        events: Box::new(events),
        shutdown,
        task,
    }
}

fn test_mib_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/integration/snmp-trap/data/VECTOR-TEST-MIB.txt")
}

fn net_snmp_target(address: SocketAddr) -> String {
    format!("udp:127.0.0.1:{}", address.port())
}

fn run_net_snmp(command: &str, args: &[String]) -> Output {
    Command::new(command)
        .arg("-V")
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "{command} is required for the SNMP trap integration tests. Install Net-SNMP and try again: {error}"
            )
        });

    let persistent_dir = std::env::temp_dir()
        .join("vector-snmp-trap-integration")
        .join(format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after the Unix epoch")
                .as_nanos()
        ));
    fs::create_dir_all(&persistent_dir).unwrap_or_else(|error| {
        panic!(
            "failed to create Net-SNMP persistent directory {}: {error}",
            persistent_dir.display()
        )
    });

    let output = Command::new(command)
        .env("MIBS", "")
        .env("SNMP_PERSISTENT_DIR", &persistent_dir)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to execute {command}: {error}"));

    assert!(
        output.status.success(),
        "{command} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    output
}

async fn next_log(events: &mut EventStream) -> LogEvent {
    let event = tokio::time::timeout(Duration::from_secs(3), events.next())
        .await
        .expect("timed out waiting for SNMP event")
        .expect("SNMP source event stream ended unexpectedly");

    event.into_log()
}

fn varbind<'a>(log: &'a LogEvent, oid: &str) -> &'a Value {
    log["varbinds"]
        .as_array()
        .expect("varbinds should be an array")
        .iter()
        .find(|varbind| varbind.get("oid") == Some(&Value::from(oid)))
        .unwrap_or_else(|| panic!("missing varbind for OID {oid}"))
}

fn assert_varbind(log: &LogEvent, oid: &str, value_type: &str, value: &str) {
    let varbind = varbind(log, oid);
    assert_eq!(varbind.get("type").unwrap(), &Value::from(value_type));
    assert_eq!(varbind.get("value").unwrap(), &Value::from(value));
}

#[tokio::test]
async fn net_snmp_v2c_trap_is_ingested_and_resolved() {
    let mut source = start_source().await;
    let target = net_snmp_target(source.address);

    run_net_snmp(
        "snmptrap",
        &[
            "-v".into(),
            "2c".into(),
            "-c".into(),
            "public".into(),
            "-t".into(),
            "1".into(),
            "-r".into(),
            "0".into(),
            target,
            String::new(),
            TRAP_OID.into(),
            VALUE_OID.into(),
            "i".into(),
            "7".into(),
            TEXT_OID.into(),
            "s".into(),
            "hello from net-snmp".into(),
            BYTES_OID.into(),
            "x".into(),
            "DE AD BE EF".into(),
        ],
    );

    let log = next_log(&mut source.events).await;
    assert_eq!(log["snmp_version"], Value::from("2c"));
    assert_eq!(log["pdu_type"], Value::from("trap_v2"));
    assert_eq!(log["community"], Value::from("public"));
    assert_eq!(log["trap_oid"], Value::from(TRAP_OID_NO_DOT));
    assert_eq!(
        log["trap_oid_name"],
        Value::from("VECTOR-TEST-MIB::vectorTestTrap")
    );

    let value = varbind(&log, VALUE_OID_NO_DOT);
    assert_eq!(
        value.get("oid_name").unwrap(),
        &Value::from("VECTOR-TEST-MIB::vectorTestValue.0")
    );
    assert_eq!(value.get("value").unwrap(), &Value::from("7"));

    let text = varbind(&log, TEXT_OID_NO_DOT);
    assert_eq!(
        text.get("value").unwrap(),
        &Value::from("hello from net-snmp")
    );

    let bytes = varbind(&log, BYTES_OID_NO_DOT);
    assert_eq!(bytes.get("value").unwrap(), &Value::from("deadbeef"));
    assert_eq!(
        bytes.get("value_bytes_hex").unwrap(),
        &Value::from("deadbeef")
    );

    source.stop().await;
}

#[tokio::test]
async fn net_snmp_v2c_trap_decodes_common_varbind_types() {
    let mut source = start_source().await;
    let target = net_snmp_target(source.address);

    run_net_snmp(
        "snmptrap",
        &[
            "-v".into(),
            "2c".into(),
            "-c".into(),
            "public".into(),
            "-t".into(),
            "1".into(),
            "-r".into(),
            "0".into(),
            target,
            String::new(),
            TRAP_OID.into(),
            VALUE_OID.into(),
            "i".into(),
            "-7".into(),
            UNSIGNED_OID.into(),
            "u".into(),
            "4294967295".into(),
            COUNTER_OID.into(),
            "c".into(),
            "123456".into(),
            TIMETICKS_OID.into(),
            "t".into(),
            "654321".into(),
            IP_ADDRESS_OID.into(),
            "a".into(),
            "192.0.2.55".into(),
            OBJECT_ID_OID.into(),
            "o".into(),
            TRAP_OID.into(),
            NULL_OID.into(),
            "n".into(),
            String::new(),
            DECIMAL_BYTES_OID.into(),
            "d".into(),
            "222 173 190 239".into(),
        ],
    );

    let log = next_log(&mut source.events).await;
    assert_eq!(log["snmp_version"], Value::from("2c"));
    assert_eq!(log["pdu_type"], Value::from("trap_v2"));
    assert_eq!(log["trap_oid"], Value::from(TRAP_OID_NO_DOT));

    assert_varbind(&log, VALUE_OID_NO_DOT, "integer", "-7");
    assert_varbind(&log, UNSIGNED_OID_NO_DOT, "gauge32", "4294967295");
    assert_varbind(&log, COUNTER_OID_NO_DOT, "counter32", "123456");
    assert_varbind(&log, TIMETICKS_OID_NO_DOT, "timeticks", "654321");
    assert_varbind(&log, IP_ADDRESS_OID_NO_DOT, "ip_address", "192.0.2.55");
    assert_varbind(
        &log,
        OBJECT_ID_OID_NO_DOT,
        "object_identifier",
        TRAP_OID_NO_DOT,
    );
    assert_varbind(&log, NULL_OID_NO_DOT, "unspecified", "unspecified");

    let decimal_bytes = varbind(&log, DECIMAL_BYTES_OID_NO_DOT);
    assert_eq!(
        decimal_bytes.get("value").unwrap(),
        &Value::from("deadbeef")
    );
    assert_eq!(
        decimal_bytes.get("value_bytes_hex").unwrap(),
        &Value::from("deadbeef")
    );

    source.stop().await;
}

#[tokio::test]
async fn net_snmp_multiple_v2c_traps_are_ingested_by_one_source() {
    let mut source = start_source().await;
    let target = net_snmp_target(source.address);

    for value in ["first", "second"] {
        run_net_snmp(
            "snmptrap",
            &[
                "-v".into(),
                "2c".into(),
                "-c".into(),
                "public".into(),
                "-t".into(),
                "1".into(),
                "-r".into(),
                "0".into(),
                target.clone(),
                String::new(),
                TRAP_OID.into(),
                TEXT_OID.into(),
                "s".into(),
                value.into(),
            ],
        );
    }

    let first = next_log(&mut source.events).await;
    let second = next_log(&mut source.events).await;

    assert_varbind(&first, TEXT_OID_NO_DOT, "octet_string", "first");
    assert_varbind(&second, TEXT_OID_NO_DOT, "octet_string", "second");

    source.stop().await;
}

#[tokio::test]
async fn net_snmp_v2c_inform_receives_response_and_is_ingested() {
    let mut source = start_source().await;
    let target = net_snmp_target(source.address);

    let args = vec![
        "-Ci".into(),
        "-v".into(),
        "2c".into(),
        "-c".into(),
        "public".into(),
        "-t".into(),
        "1".into(),
        "-r".into(),
        "0".into(),
        target,
        String::new(),
        TRAP_OID.into(),
        VALUE_OID.into(),
        "i".into(),
        "9".into(),
    ];
    let command = tokio::task::spawn_blocking(move || run_net_snmp("snmptrap", &args));

    let log = next_log(&mut source.events).await;
    assert_eq!(log["snmp_version"], Value::from("2c"));
    assert_eq!(log["pdu_type"], Value::from("inform_request"));
    assert_eq!(log["trap_oid"], Value::from(TRAP_OID_NO_DOT));
    assert_eq!(
        log["trap_oid_name"],
        Value::from("VECTOR-TEST-MIB::vectorTestTrap")
    );
    assert!(log["request_id"].as_integer().is_some());

    let output = tokio::time::timeout(Duration::from_secs(3), command)
        .await
        .expect("snmptrap -Ci should finish after receiving Vector's response")
        .expect("snmptrap -Ci task should not panic");

    assert!(
        !String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("timeout"),
        "snmptrap -Ci should receive Vector's RFC 3416 response, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    source.stop().await;
}

#[tokio::test]
async fn net_snmp_v1_enterprise_specific_trap_is_ingested() {
    let mut source = start_source().await;
    let target = net_snmp_target(source.address);

    run_net_snmp(
        "snmptrap",
        &[
            "-v".into(),
            "1".into(),
            "-c".into(),
            "public".into(),
            "-t".into(),
            "1".into(),
            "-r".into(),
            "0".into(),
            target,
            ENTERPRISE_OID.into(),
            "127.0.0.1".into(),
            "6".into(),
            "42".into(),
            String::new(),
            VALUE_OID.into(),
            "i".into(),
            "11".into(),
        ],
    );

    let log = next_log(&mut source.events).await;
    assert_eq!(log["snmp_version"], Value::from("1"));
    assert_eq!(log["pdu_type"], Value::from("trap_v1"));
    assert_eq!(log["community"], Value::from("public"));
    assert_eq!(log["generic_trap"], Value::from(6));
    assert_eq!(log["specific_trap"], Value::from(42));
    assert_eq!(
        log["enterprise_oid_name"],
        Value::from("VECTOR-TEST-MIB::vectorTestRoot")
    );

    let value = varbind(&log, VALUE_OID_NO_DOT);
    assert_eq!(
        value.get("oid_name").unwrap(),
        &Value::from("VECTOR-TEST-MIB::vectorTestValue.0")
    );
    assert_eq!(value.get("value").unwrap(), &Value::from("11"));

    source.stop().await;
}
