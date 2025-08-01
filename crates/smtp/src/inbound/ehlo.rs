/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant, SystemTime};

use crate::{core::Session, scripts::ScriptResult};
use common::{
    config::smtp::session::{Mechanism, Stage},
    listener::SessionStream,
};

use mail_auth::{
    SpfResult,
    spf::verify::{HasValidLabels, SpfParameters},
};
use smtp_proto::*;
use trc::SmtpEvent;

impl<T: SessionStream> Session<T> {
    pub async fn handle_ehlo(&mut self, domain: String, is_extended: bool) -> Result<(), ()> {
        // Set EHLO domain

        if domain != self.data.helo_domain {
            // Reject non-FQDN EHLO domains - simply checks that the hostname has at least one dot
            if self.params.ehlo_reject_non_fqdn && !domain.as_str().has_valid_labels() {
                trc::event!(
                    Smtp(SmtpEvent::InvalidEhlo),
                    SpanId = self.data.session_id,
                    Domain = domain,
                );

                return self.write(b"550 5.5.0 Invalid EHLO domain.\r\n").await;
            }

            trc::event!(
                Smtp(SmtpEvent::Ehlo),
                SpanId = self.data.session_id,
                Domain = domain.clone(),
            );

            // SPF check
            let prev_helo_domain = std::mem::replace(&mut self.data.helo_domain, domain);
            if self.params.spf_ehlo.verify() {
                let time = Instant::now();
                let spf_output = self
                    .server
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_spf(self.server.inner.cache.build_auth_parameters(
                        SpfParameters::verify_ehlo(
                            self.data.remote_ip,
                            &self.data.helo_domain,
                            &self.hostname,
                        ),
                    ))
                    .await;

                trc::event!(
                    Smtp(if matches!(spf_output.result(), SpfResult::Pass) {
                        SmtpEvent::SpfEhloPass
                    } else {
                        SmtpEvent::SpfEhloFail
                    }),
                    SpanId = self.data.session_id,
                    Domain = self.data.helo_domain.clone(),
                    Result = trc::Error::from(&spf_output),
                    Elapsed = time.elapsed(),
                );

                if self
                    .handle_spf(&spf_output, self.params.spf_ehlo.is_strict())
                    .await?
                {
                    self.data.spf_ehlo = spf_output.into();
                } else {
                    self.data.mail_from = None;
                    self.data.helo_domain = prev_helo_domain;
                    return Ok(());
                }
            }

            // Sieve filtering
            if let Some((script, script_id)) = self
                .server
                .eval_if::<String, _>(
                    &self.server.core.smtp.session.ehlo.script,
                    self,
                    self.data.session_id,
                )
                .await
                .and_then(|name| {
                    self.server
                        .get_trusted_sieve_script(&name, self.data.session_id)
                        .map(|s| (s, name))
                })
            {
                if let ScriptResult::Reject(message) = self
                    .run_script(
                        script_id,
                        script.clone(),
                        self.build_script_parameters("ehlo"),
                    )
                    .await
                {
                    self.data.mail_from = None;
                    self.data.helo_domain = prev_helo_domain;
                    self.data.spf_ehlo = None;
                    return self.write(message.as_bytes()).await;
                }
            }

            // Milter filtering
            if let Err(message) = self.run_milters(Stage::Ehlo, None).await {
                self.data.mail_from = None;
                self.data.helo_domain = prev_helo_domain;
                self.data.spf_ehlo = None;
                return self.write(message.message.as_bytes()).await;
            }

            // MTAHook filtering
            if let Err(message) = self.run_mta_hooks(Stage::Ehlo, None, None).await {
                self.data.mail_from = None;
                self.data.helo_domain = prev_helo_domain;
                self.data.spf_ehlo = None;
                return self.write(message.message.as_bytes()).await;
            }
        }

        // Reset
        if self.data.mail_from.is_some() {
            self.reset();
        }

        if !is_extended {
            return self
                .write(format!("250 {} you had me at HELO\r\n", self.hostname).as_bytes())
                .await;
        }

        let mut response = EhloResponse::new(self.hostname.as_str());
        response.capabilities =
            EXT_ENHANCED_STATUS_CODES | EXT_8BIT_MIME | EXT_BINARY_MIME | EXT_SMTP_UTF8;
        if !self.stream.is_tls() && self.instance.acceptor.is_tls() {
            response.capabilities |= EXT_START_TLS;
        }
        let ec = &self.server.core.smtp.session.extensions;
        let ac = &self.server.core.smtp.session.auth;
        let dc = &self.server.core.smtp.session.data;

        // Pipelining
        if self
            .server
            .eval_if(&ec.pipelining, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            response.capabilities |= EXT_PIPELINING;
        }

        // Chunking
        if self
            .server
            .eval_if(&ec.chunking, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            response.capabilities |= EXT_CHUNKING;
        }

        // Address Expansion
        if self
            .server
            .eval_if(&ec.expn, self, self.data.session_id)
            .await
            .unwrap_or(false)
        {
            response.capabilities |= EXT_EXPN;
        }

        // Recipient Verification
        if self
            .server
            .eval_if(&ec.vrfy, self, self.data.session_id)
            .await
            .unwrap_or(false)
        {
            response.capabilities |= EXT_VRFY;
        }

        // Require TLS
        if self
            .server
            .eval_if(&ec.requiretls, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            response.capabilities |= EXT_REQUIRE_TLS;
        }

        // DSN
        if self
            .server
            .eval_if(&ec.dsn, self, self.data.session_id)
            .await
            .unwrap_or(false)
        {
            response.capabilities |= EXT_DSN;
        }

        // Authentication
        if !self.is_authenticated() {
            response.auth_mechanisms = self
                .server
                .eval_if::<Mechanism, _>(&ac.mechanisms, self, self.data.session_id)
                .await
                .unwrap_or_default()
                .into();
            if response.auth_mechanisms != 0 {
                response.capabilities |= EXT_AUTH;
            }
        }

        // Future release
        if let Some(value) = self
            .server
            .eval_if::<Duration, _>(&ec.future_release, self, self.data.session_id)
            .await
        {
            response.capabilities |= EXT_FUTURE_RELEASE;
            response.future_release_interval = value.as_secs();
            response.future_release_datetime = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                + value.as_secs();
        }

        // Deliver By
        if let Some(value) = self
            .server
            .eval_if::<Duration, _>(&ec.deliver_by, self, self.data.session_id)
            .await
        {
            response.capabilities |= EXT_DELIVER_BY;
            response.deliver_by = value.as_secs();
        }

        // Priority
        if let Some(value) = self
            .server
            .eval_if::<MtPriority, _>(&ec.mt_priority, self, self.data.session_id)
            .await
        {
            response.capabilities |= EXT_MT_PRIORITY;
            response.mt_priority = value;
        }

        // Size
        response.size = self
            .server
            .eval_if(&dc.max_message_size, self, self.data.session_id)
            .await
            .unwrap_or(25 * 1024 * 1024);
        if response.size > 0 {
            response.capabilities |= EXT_SIZE;
        }

        // No soliciting
        if let Some(value) = self
            .server
            .eval_if::<String, _>(&ec.no_soliciting, self, self.data.session_id)
            .await
        {
            response.capabilities |= EXT_NO_SOLICITING;
            response.no_soliciting = if !value.is_empty() {
                value.to_string().into()
            } else {
                None
            };
        }

        // Generate response
        let mut buf = Vec::with_capacity(64);
        response.write(&mut buf).ok();
        self.write(&buf).await
    }
}
