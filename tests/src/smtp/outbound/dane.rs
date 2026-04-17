/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::{TestMessage, TestQueueEvent, TestReportingEvent},
        session::{TestSession, VerifyResponse},
    },
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use common::{
    config::smtp::resolver::{Tlsa, TlsaEntry},
    ipc::PolicyType,
};
use mail_auth::{
    MX,
    common::parse::TxtRecordParser,
    mta_sts::{ReportUri, TlsRpt},
    report::tlsrpt::ResultType,
};
use registry::schema::{
    enums::MtaRequiredOrOptional,
    prelude::ObjectType,
    structs::{Expression, MtaTlsStrategy, TlsReportSettings},
};
use rustls_pki_types::CertificateDer;
use smtp::outbound::dane::{dnssec::TlsaLookup, verify::TlsaVerify};
use smtp::queue::{Error, ErrorDetails, Status};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader},
    num::ParseIntError,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

#[tokio::test]
#[serial_test::serial]
async fn dane_verify() {
    let mut local = TestServerBuilder::new("smtp_dane_local")
        .await
        .with_http_listener(19018)
        .await
        .disable_services()
        .capture_queue()
        .capture_reporting()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_dane_remote")
        .await
        .with_dummy_tls_cert(["*.foobar.org"])
        .await
        .with_http_listener(19019)
        .await
        .with_smtp_listener(9925)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_allow_relaying().await;
    local_admin.mta_no_auth().await;
    local_admin
        .registry_create_object(TlsReportSettings {
            send_frequency: Expression {
                else_: "weekly".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    let (tls_strategy_id, mut tls_strategy) = local_admin
        .registry_get_all::<MtaTlsStrategy>()
        .await
        .into_iter()
        .find(|(_, s)| s.name == "default")
        .unwrap();
    tls_strategy.dane = MtaRequiredOrOptional::Require;
    tls_strategy.start_tls = MtaRequiredOrOptional::Require;
    let mut tls_strategy = serde_json::to_value(tls_strategy).unwrap();
    tls_strategy
        .as_object_mut()
        .unwrap()
        .retain(|k, _| k != "name");
    local_admin
        .registry_update_object(ObjectType::MtaTlsStrategy, tls_strategy_id, tls_strategy)
        .await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_no_auth().await;
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_add_all_headers().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    // Add mock DNS entries
    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    local.server.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    local.server.txt_add(
        "_smtp._tls.foobar.org",
        TlsRpt::parse(b"v=TLSRPTv1; rua=mailto:reports@foobar.org").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local
        .expect_message()
        .await
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No TLSA reco=")
        .assert_contains("rds found");
    local.read_event().await.assert_done();
    local.assert_no_events();

    // Expect TLS failure report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.domain, "foobar.org");
    assert_eq!(report.policy, PolicyType::Tlsa(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::DaneRequired
    );
    assert_eq!(
        report.failure.as_ref().unwrap().receiving_mx_hostname,
        Some("mx.foobar.org".to_string())
    );
    assert_eq!(
        report.tls_record.rua,
        vec![ReportUri::Mail("reports@foobar.org".to_string())]
    );

    // DANE failure with no matching certificates
    let tlsa = Arc::new(Tlsa {
        entries: vec![TlsaEntry {
            is_end_entity: true,
            is_sha256: true,
            is_spki: true,
            data: vec![1, 2, 3],
        }],
        has_end_entities: true,
        has_intermediates: false,
    });
    local.server.tlsa_add(
        "_25._tcp.mx.foobar.org",
        tlsa.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local
        .expect_message()
        .await
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No matching ")
        .assert_contains("certificates found");
    local.read_event().await.assert_done();
    local.assert_no_events();

    // Expect TLS failure report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::ValidationFailure
    );
    remote.assert_no_events();

    // DANE successful delivery
    let tlsa = Arc::new(Tlsa {
        entries: vec![TlsaEntry {
            is_end_entity: true,
            is_sha256: true,
            is_spki: true,
            data: vec![
                73, 186, 44, 106, 13, 198, 100, 180, 0, 44, 158, 188, 15, 195, 39, 198, 61, 254,
                215, 237, 100, 26, 15, 155, 219, 235, 120, 64, 128, 172, 17, 0,
            ],
        }],
        has_end_entities: true,
        has_intermediates: false,
    });
    local.server.tlsa_add(
        "_25._tcp.mx.foobar.org",
        tlsa.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local.read_event().await.assert_done();
    local.assert_no_events();
    remote
        .expect_message()
        .await
        .read_lines(&remote)
        .await
        .assert_contains("using TLSv1.3 with cipher");

    // Expect TLS success report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert!(report.failure.is_none());
}

#[tokio::test]
async fn dane_test() {
    let test = TestServerBuilder::new("smtp_dane_remote")
        .await
        .with_http_listener(19036)
        .await
        .disable_services()
        .build()
        .await;

    // Add dns entries
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("smtp");
    path.push("dane");
    let mut file = path.clone();
    file.push("dns.txt");

    let mut hosts = BTreeSet::new();
    let mut tlsa = Tlsa {
        entries: Vec::new(),
        has_end_entities: false,
        has_intermediates: false,
    };
    let mut hostname = String::new();

    for line in BufReader::new(File::open(file).unwrap()).lines() {
        let line = line.unwrap();
        let mut is_end_entity = false;
        for (pos, item) in line.split_whitespace().enumerate() {
            match pos {
                0 => {
                    if hostname != item && !hostname.is_empty() {
                        test.server.tlsa_add(
                            hostname,
                            tlsa.into(),
                            Instant::now() + Duration::from_secs(30),
                        );
                        tlsa = Tlsa {
                            entries: Vec::new(),
                            has_end_entities: false,
                            has_intermediates: false,
                        };
                    }
                    hosts.insert(item.strip_prefix("_25._tcp.").unwrap().to_string());
                    hostname = item.to_string();
                }
                1 => {
                    is_end_entity = item == "3";
                }
                4 => {
                    if is_end_entity {
                        tlsa.has_end_entities = true;
                    } else {
                        tlsa.has_intermediates = true;
                    }
                    tlsa.entries.push(TlsaEntry {
                        is_end_entity,
                        is_sha256: true,
                        is_spki: true,
                        data: decode_hex(item).unwrap(),
                    });
                }
                _ => (),
            }
        }
    }
    test.server.tlsa_add(
        hostname,
        tlsa.into(),
        Instant::now() + Duration::from_secs(30),
    );

    // Add certificates
    assert!(!hosts.is_empty());
    for host in hosts {
        // Add certificates
        let mut certs = Vec::new();
        for num in 0..6 {
            let mut file = path.clone();
            file.push(format!("{host}.{num}.cert"));
            if file.exists() {
                certs.push(CertificateDer::from(fs::read(file).unwrap()));
            } else {
                break;
            }
        }

        // Successful DANE verification
        let tlsa = test
            .server
            .tlsa_lookup(format!("_25._tcp.{host}."))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(tlsa.verify(0, &host, Some(&certs)), Ok(()));

        // Failed DANE verification
        certs.remove(0);
        assert_eq!(
            tlsa.verify(0, &host, Some(&certs)),
            Err(Status::PermanentFailure(ErrorDetails {
                entity: host.into(),
                details: Error::DaneError("No matching certificates found in TLSA records".into())
            }))
        );
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
