/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, net::IpAddr, sync::Arc, time::Instant};

use compact_str::ToCompactString;
use rustls::ServerConfig;
use std::fmt::Debug;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};
use tokio_rustls::{Accept, TlsAcceptor};
use trc::{Event, EventType, Key};
use utils::{config::ipmask::IpAddrMask, snowflake::SnowflakeIdGenerator};

use crate::{
    Server,
    config::server::ServerProtocol,
    expr::{functions::ResolveVariable, *},
};

use self::limiter::{ConcurrencyLimiter, InFlight};

pub mod acme;
pub mod asn;
pub mod blocked;
pub mod limiter;
pub mod listen;
pub mod stream;
pub mod tls;

pub struct ServerInstance {
    pub id: String,
    pub protocol: ServerProtocol,
    pub acceptor: TcpAcceptor,
    pub limiter: ConcurrencyLimiter,
    pub proxy_networks: Vec<IpAddrMask>,
    pub shutdown_rx: watch::Receiver<bool>,
    pub span_id_gen: Arc<SnowflakeIdGenerator>,
}

#[derive(Default)]
pub enum TcpAcceptor {
    Tls {
        config: Arc<ServerConfig>,
        acceptor: TlsAcceptor,
        implicit: bool,
    },
    #[default]
    Plain,
}

#[allow(clippy::large_enum_variant)]
pub enum TcpAcceptorResult<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    Tls(Accept<IO>),
    Plain(IO),
    Close,
}

pub struct SessionData<T: SessionStream> {
    pub stream: T,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: ServerProtocol,
    pub session_id: u64,
    pub in_flight: InFlight,
    pub instance: Arc<ServerInstance>,
}

pub trait SessionStream: AsyncRead + AsyncWrite + Unpin + 'static + Sync + Send {
    fn is_tls(&self) -> bool;
    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionResult {
    Continue,
    Close,
    UpgradeTls,
}

pub trait SessionManager: Sync + Send + 'static + Clone {
    fn spawn<T: SessionStream>(
        &self,
        mut session: SessionData<T>,
        is_tls: bool,
        acme_core: Option<Server>,
        span_start: EventType,
        span_end: EventType,
    ) {
        let manager = self.clone();

        tokio::spawn(async move {
            let start_time = Instant::now();
            let local_port = session.local_port;
            let session_id;

            if is_tls {
                match session
                    .instance
                    .acceptor
                    .accept(session.stream, acme_core, &session.instance)
                    .await
                {
                    TcpAcceptorResult::Tls(accept) => match accept.await {
                        Ok(stream) => {
                            // Generate sessionId
                            session.session_id = session.instance.span_id_gen.generate();
                            session_id = session.session_id;

                            // Send span
                            Event::with_keys(
                                span_start,
                                vec![
                                    (Key::ListenerId, session.instance.id.clone().into()),
                                    (Key::LocalPort, session.local_port.into()),
                                    (Key::RemoteIp, session.remote_ip.into()),
                                    (Key::RemotePort, session.remote_port.into()),
                                    (Key::SpanId, session.session_id.into()),
                                ],
                            )
                            .send_with_metrics();

                            manager
                                .handle(SessionData {
                                    stream,
                                    local_ip: session.local_ip,
                                    local_port: session.local_port,
                                    remote_ip: session.remote_ip,
                                    remote_port: session.remote_port,
                                    protocol: session.protocol,
                                    session_id: session.session_id,
                                    in_flight: session.in_flight,
                                    instance: session.instance,
                                })
                                .await;
                        }
                        Err(err) => {
                            trc::event!(
                                Tls(trc::TlsEvent::HandshakeError),
                                ListenerId = session.instance.id.clone(),
                                LocalPort = local_port,
                                RemoteIp = session.remote_ip,
                                RemotePort = session.remote_port,
                                Reason = err.to_string(),
                            );

                            return;
                        }
                    },
                    TcpAcceptorResult::Plain(stream) => {
                        // Generate sessionId
                        session.session_id = session.instance.span_id_gen.generate();
                        session_id = session.session_id;

                        // Send span
                        Event::with_keys(
                            span_start,
                            vec![
                                (Key::ListenerId, session.instance.id.clone().into()),
                                (Key::LocalPort, session.local_port.into()),
                                (Key::RemoteIp, session.remote_ip.into()),
                                (Key::RemotePort, session.remote_port.into()),
                                (Key::SpanId, session.session_id.into()),
                            ],
                        )
                        .send_with_metrics();

                        session.stream = stream;
                        manager.handle(session).await;
                    }
                    TcpAcceptorResult::Close => return,
                }
            } else {
                // Generate sessionId
                session.session_id = session.instance.span_id_gen.generate();
                session_id = session.session_id;

                // Send span
                Event::with_keys(
                    span_start,
                    vec![
                        (Key::ListenerId, session.instance.id.clone().into()),
                        (Key::LocalPort, session.local_port.into()),
                        (Key::RemoteIp, session.remote_ip.into()),
                        (Key::RemotePort, session.remote_port.into()),
                        (Key::SpanId, session.session_id.into()),
                    ],
                )
                .send_with_metrics();

                manager.handle(session).await;
            }

            // End span
            Event::with_keys(
                span_end,
                vec![
                    (Key::SpanId, session_id.into()),
                    (Key::Elapsed, start_time.elapsed().into()),
                ],
            )
            .send_with_metrics();
        });
    }

    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send;

    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send;
}

impl<T: SessionStream> ResolveVariable for SessionData<T> {
    fn resolve_variable(&self, variable: u32) -> crate::expr::Variable<'_> {
        match variable {
            V_REMOTE_IP => self.remote_ip.to_compact_string().into(),
            V_REMOTE_PORT => self.remote_port.into(),
            V_LOCAL_IP => self.local_ip.to_compact_string().into(),
            V_LOCAL_PORT => self.local_port.into(),
            V_LISTENER => self.instance.id.as_str().into(),
            V_PROTOCOL => self.protocol.as_str().into(),
            V_TLS => self.stream.is_tls().into(),
            _ => crate::expr::Variable::default(),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

impl Debug for TcpAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls {
                config, implicit, ..
            } => f
                .debug_struct("Tls")
                .field("config", config)
                .field("implicit", implicit)
                .finish(),
            Self::Plain => write!(f, "Plain"),
        }
    }
}
