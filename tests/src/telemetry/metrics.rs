/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use common::telemetry::metrics::store::MetricsStore;
use registry::{schema::prelude::ObjectType, types::datetime::UTCDateTime};
use std::time::Duration;
use store::write::now;
use types::id::Id;

pub async fn test(test: &TestServer) {
    println!("Running Metrics tests...");

    // Make sure there are no span entries in the db
    let admin = test.account("admin@example.org");
    assert_eq!(
        admin
            .registry_query(
                ObjectType::Metric,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>(),
        Vec::<Id>::new()
    );

    // Insert test metrics
    test.server.insert_test_metrics().await;

    // Fetch all metrics
    let metric_ids = admin
        .registry_query(
            ObjectType::Metric,
            Vec::<(&str, &str)>::new(),
            Vec::<&str>::new(),
        )
        .await
        .object_ids()
        .collect::<Vec<_>>();
    let response = admin
        .registry_get_many(ObjectType::Metric, Vec::<&str>::new())
        .await;
    let metrics = response.list();
    assert!(
        metrics.len() > 2000,
        "Found {} metrics, expected more than 2000",
        metrics.len()
    );
    assert_eq!(metrics.len(), metric_ids.len());

    // Fetch the last 48 hours of metrics
    let metric_ids = admin
        .registry_query(
            ObjectType::Metric,
            [(
                "timestampIsGreaterThan",
                UTCDateTime::from_timestamp((now() - (2 * 86400)) as i64).to_string(),
            )],
            Vec::<&str>::new(),
        )
        .await
        .object_ids()
        .collect::<Vec<_>>();
    assert!(
        metric_ids.len() > 20 && metric_ids.len() < 2000,
        "Found {} metrics, expected more than 20 and less than 2000",
        metric_ids.len()
    );

    // Purge metrics and make sure they are gone
    test.server
        .metrics_store()
        .purge_metrics(Duration::from_secs(0))
        .await
        .unwrap();
    assert_eq!(
        admin
            .registry_query(
                ObjectType::Metric,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>(),
        Vec::<Id>::new()
    );
}
