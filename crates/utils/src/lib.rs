/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod bimap;
pub mod cache;
pub mod chained_bytes;
pub mod cheeky_hash;
pub mod codec;
pub mod cron;
pub mod glob;
pub mod http;
pub mod map;
pub mod snowflake;
pub mod template;
pub mod tls;
pub mod topological;
pub mod url_params;

use compact_str::ToCompactString;
use futures::StreamExt;
pub use reqwest::Client;
use reqwest::Response;
pub use reqwest::header::HeaderMap;
use std::fmt::Write;

pub trait HttpLimitResponse: Sync + Send {
    fn bytes_with_limit(
        self,
        limit: usize,
    ) -> impl std::future::Future<Output = reqwest::Result<Option<Vec<u8>>>> + Send;
}

impl HttpLimitResponse for Response {
    async fn bytes_with_limit(self, limit: usize) -> reqwest::Result<Option<Vec<u8>>> {
        if self
            .content_length()
            .is_some_and(|len| len as usize > limit)
        {
            return Ok(None);
        }

        let mut bytes = Vec::with_capacity(std::cmp::min(limit, 1024));
        let mut stream = self.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len() + chunk.len() > limit {
                return Ok(None);
            }
            bytes.extend_from_slice(&chunk);
        }

        Ok(Some(bytes))
    }
}

pub trait UnwrapFailure<T> {
    fn failed(self, action: &str) -> T;
}

impl<T> UnwrapFailure<T> for Option<T> {
    fn failed(self, message: &str) -> T {
        match self {
            Some(result) => result,
            None => {
                trc::event!(
                    Server(trc::ServerEvent::StartupError),
                    Details = message.to_compact_string()
                );
                eprintln!("{message}");
                std::process::exit(1);
            }
        }
    }
}

impl<T, E: std::fmt::Display> UnwrapFailure<T> for Result<T, E> {
    fn failed(self, message: &str) -> T {
        match self {
            Ok(result) => result,
            Err(err) => {
                trc::event!(
                    Server(trc::ServerEvent::StartupError),
                    Details = message.to_compact_string(),
                    Reason = err.to_compact_string()
                );

                #[cfg(feature = "test_mode")]
                panic!("{message}: {err}");

                #[cfg(not(feature = "test_mode"))]
                {
                    eprintln!("{message}: {err}");
                    std::process::exit(1);
                }
            }
        }
    }
}

pub fn failed(message: &str) -> ! {
    trc::event!(
        Server(trc::ServerEvent::StartupError),
        Details = message.to_compact_string(),
    );
    eprintln!("{message}");
    std::process::exit(1);
}

pub async fn wait_for_shutdown() {
    #[cfg(not(target_env = "msvc"))]
    let signal = {
        use tokio::signal::unix::{SignalKind, signal};

        let mut h_term = signal(SignalKind::terminate()).failed("start signal handler");
        let mut h_int = signal(SignalKind::interrupt()).failed("start signal handler");

        tokio::select! {
            _ = h_term.recv() => "SIGTERM",
            _ = h_int.recv() => "SIGINT",
        }
    };

    #[cfg(target_env = "msvc")]
    let signal = {
        match tokio::signal::ctrl_c().await {
            Ok(()) => "SIGINT",
            Err(err) => {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "Unable to listen for shutdown signal",
                    Reason = err.to_string(),
                );
                "Error"
            }
        }
    };

    trc::event!(Server(trc::ServerEvent::Shutdown), CausedBy = signal);
}

pub trait DomainPart {
    fn to_lowercase_domain(&self) -> String;
    fn domain_part(&self) -> &str;
    fn try_domain_part(&self) -> Option<&str>;
    fn try_local_part(&self) -> Option<&str>;
}

impl<T: AsRef<str>> DomainPart for T {
    fn to_lowercase_domain(&self) -> String {
        let address = self.as_ref();
        if let Some((local, domain)) = address.rsplit_once('@') {
            let mut address = String::with_capacity(address.len());
            address.push_str(local);
            address.push('@');
            for ch in domain.chars() {
                for ch in ch.to_lowercase() {
                    address.push(ch);
                }
            }
            address
        } else {
            address.to_string()
        }
    }

    #[inline(always)]
    fn try_domain_part(&self) -> Option<&str> {
        self.as_ref().rsplit_once('@').map(|(_, d)| d)
    }

    #[inline(always)]
    fn try_local_part(&self) -> Option<&str> {
        self.as_ref().rsplit_once('@').map(|(l, _)| l)
    }

    #[inline(always)]
    fn domain_part(&self) -> &str {
        self.as_ref()
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or_default()
    }
}

pub trait HexEncode {
    fn hex_encode(&self) -> String;
}

impl<T: AsRef<[u8]>> HexEncode for T {
    fn hex_encode(&self) -> String {
        let bytes = self.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }
}

static NIL_CHAR: char = char::from_u32(0).unwrap();

// Basic email sanitizer
pub fn sanitize_email(email: &str) -> Option<String> {
    let mut result = String::with_capacity(email.len());
    let mut last_ch = NIL_CHAR;
    let mut chars = email.chars();

    for ch in chars.by_ref() {
        match ch {
            '.' | '+' | '-' | '_' => {
                if !last_ch.is_alphanumeric() {
                    return None;
                }
                result.push(ch);
            }
            ' ' | '\x09'..='\x0d' => continue,
            '@' => {
                if result.is_empty() || last_ch == '.' {
                    return None;
                }
                last_ch = ch;
                result.push(ch);
                break;
            }
            _ => {
                if ch.is_uppercase() {
                    for ch in ch.to_lowercase() {
                        result.push(ch);
                    }
                } else if ch.is_alphanumeric() {
                    result.push(ch);
                } else {
                    return None;
                }
            }
        }

        last_ch = ch;
    }

    if last_ch != '@' {
        return None;
    }

    last_ch = NIL_CHAR;

    for ch in chars {
        match ch {
            '.' | '-' | '_' => {
                if !last_ch.is_alphanumeric() {
                    return None;
                }
                result.push(ch);
            }
            ' ' | '\x09'..='\x0d' => continue,
            _ => {
                if ch.is_uppercase() {
                    for ch in ch.to_lowercase() {
                        result.push(ch);
                    }
                } else if ch.is_alphanumeric() {
                    result.push(ch);
                } else {
                    return None;
                }
            }
        }

        last_ch = ch;
    }

    if last_ch.is_alphanumeric()
        && psl::domain(result.as_bytes()).is_some_and(|d| d.suffix().typ().is_some())
    {
        Some(result)
    } else {
        None
    }
}

pub fn sanitize_email_local(local: &str) -> Option<String> {
    let mut result = String::with_capacity(local.len());
    let mut last_ch = NIL_CHAR;

    for ch in local.chars() {
        match ch {
            '.' | '+' | '-' | '_' => {
                if !last_ch.is_alphanumeric() {
                    return None;
                }
                result.push(ch);
            }
            ' ' | '\x09'..='\x0d' => continue,
            _ => {
                if ch.is_uppercase() {
                    for ch in ch.to_lowercase() {
                        result.push(ch);
                    }
                } else if ch.is_alphanumeric() {
                    result.push(ch);
                } else {
                    return None;
                }
            }
        }

        last_ch = ch;
    }

    if !result.is_empty() && last_ch != '.' {
        Some(result)
    } else {
        None
    }
}

pub fn sanitize_domain(domain: &str) -> Option<String> {
    let mut result = String::with_capacity(domain.len());
    let mut found_dot = false;
    let mut last_ch = char::from(0);

    for ch in domain.chars() {
        if !ch.is_whitespace() {
            if ch == '.' {
                found_dot = true;
                if !(last_ch.is_alphanumeric() || last_ch == '-' || last_ch == '_') {
                    return None;
                }
            }
            last_ch = ch;
            for ch in ch.to_lowercase() {
                result.push(ch);
            }
        }
    }

    if found_dot
        && last_ch != '.'
        && psl::domain(result.as_bytes()).is_some_and(|d| d.suffix().typ().is_some())
    {
        Some(result)
    } else {
        None
    }
}
