/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::network::acme::{AcmeError, AcmeResult};
use chrono::{DateTime, Utc};
use hyper::{
    Method, StatusCode,
    header::{CONTENT_TYPE, USER_AGENT},
};
use reqwest::Response;
use std::time::Duration;

#[allow(unused_mut)]
pub(crate) async fn https(
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
    max_retries: u32,
) -> AcmeResult<Response> {
    let url = url.as_ref();
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .http1_only();

    #[cfg(any(feature = "dev_mode", feature = "test_mode"))]
    {
        builder = builder.danger_accept_invalid_certs(
            url.starts_with("https://localhost") || url.starts_with("https://127.0.0.1"),
        );
    }

    let mut request = builder
        .build()?
        .request(method, url)
        .header(USER_AGENT, crate::USER_AGENT);

    if let Some(body) = body {
        request = request
            .header(CONTENT_TYPE, "application/jose+json")
            .body(body);
    }

    let response = request.send().await?;
    if response.status().is_success() {
        Ok(response)
    } else if matches!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    ) {
        Err(AcmeError::Backoff {
            wait: parse_retry_after(&response),
            max_retries,
        })
    } else {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        Err(AcmeError::HttpStatus(format!(
            "Unexpected status {}: {}",
            status, text
        )))
    }
}

pub(crate) fn get_header(response: &Response, header: &'static str) -> AcmeResult<String> {
    match response.headers().get_all(header).iter().next_back() {
        Some(value) => Ok(value
            .to_str()
            .map_err(|err| {
                AcmeError::Invalid(format!("Failed to read header {}: {}", header, err))
            })?
            .to_string()),
        None => Err(AcmeError::Invalid(format!("Missing header: {}", header))),
    }
}

pub(crate) fn parse_retry_after(response: &Response) -> Option<Duration> {
    let value = response.headers().get("Retry-After")?.to_str().ok()?;
    if let Ok(secs) = value.parse::<u64>() {
        Some(Duration::from_secs(secs + 1))
    } else if let Ok(dt) = DateTime::parse_from_rfc2822(value) {
        Utc::now()
            .signed_duration_since(dt.with_timezone(&Utc))
            .to_std()
            .map(|dur| dur + Duration::from_secs(1))
            .ok()
    } else {
        None
    }
}
