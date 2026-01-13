#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use std::{
    collections::HashMap,
    convert::Infallible,
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::Path,
    http::StatusCode,
    routing::{get, post},
};
use axum_client_ip::RightmostXForwardedFor;
use clickhouse::{Row, inserter::Inserter};
use eyre::{Context, eyre};
use log::{error, info, warn};
use netty::{Handshake, ReadError};
use parking_lot::RwLock;
use quinn::{
    ConnectionError, Endpoint, Incoming, ServerConfig, TransportConfig, VarInt,
    crypto::rustls::QuicServerConfig,
    rustls::pki_types::{CertificateDer, PrivateKeyDer},
};
use routing::RoutingTable;
use rustls_pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use crate::{
    netty::{ReadExt, WriteExt, read_varint},
    proto::{ClientboundControlMessage, ServerboundControlMessage},
    routing::RouterRequest,
};

mod netty;
mod proto;
mod routing;
mod unicode_madness;
mod wordlist;

fn get_certs() -> eyre::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert_file = std::io::BufReader::new(std::fs::File::open(
        std::env::var("QUICLIME_CERT_PATH").context("Reading QUICLIME_CERT_PATH")?,
    )?);
    let certs = rustls_pki_types::pem::ReadIter::new(&mut cert_file)
        .filter_map(Result::ok)
        .collect();
    let key = PrivateKeyDer::from_pem_file(
        std::env::var("QUICLIME_KEY_PATH").context("Reading QUICLIME_KEY_PATH")?,
    )?;
    Ok((certs, key))
}

async fn create_server_config() -> eyre::Result<ServerConfig> {
    let (cert_chain, key_der) = tokio::task::spawn_blocking(get_certs).await??;
    let mut rustls_config = quinn::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;
    rustls_config.alpn_protocols = vec![b"quiclime".to_vec()];
    let quic_rustls_config = QuicServerConfig::try_from(rustls_config)?;
    let mut config = ServerConfig::with_crypto(Arc::new(quic_rustls_config));
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .keep_alive_interval(Some(Duration::from_secs(5)));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[derive(Row, Serialize)]
struct Connection {
    #[serde(with = "clickhouse::serde::time::datetime")]
    established: OffsetDateTime,
    region: &'static str,
    client: Ipv6Addr,
    intent: &'static str,
    outcome: &'static str,
    target: String,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    env_logger::init();
    // JUSTIFICATION: this lives until the end of the entire program
    let endpoint = Box::leak(Box::new(Endpoint::server(
        create_server_config().await?,
        std::env::var("QUICLIME_BIND_ADDR_QUIC")
            .context("Reading QUICLIME_BIND_ADDR_QUIC")?
            .parse()?,
    )?));
    // JUSTIFICATION: this lives until the end of the entire program
    let routing_table = Box::leak(Box::new(routing::RoutingTable::new(
        std::env::var("QUICLIME_BASE_DOMAIN").context("Reading QUICLIME_BASE_DOMAIN")?,
    )));

    let client = clickhouse::Client::default()
        .with_url(std::env::var("CLICKHOUSE_URL").context("Reading CLICKHOUSE_URL")?)
        .with_user(std::env::var("CLICKHOUSE_USER").context("Reading CLICKHOUSE_USER")?)
        .with_password(
            tokio::fs::read_to_string(
                std::env::var("CLICKHOUSE_PASSWORD_PATH")
                    .context("Reading CLICKHOUSE_PASSWORD_PATH")?,
            )
            .await
            .context("Reading from CLICKHOUSE_PASSWORD_PATH")?,
        )
        .with_database(std::env::var("CLICKHOUSE_DB").context("Reading CLICKHOUSE_DB")?);
    let inserter: clickhouse::inserter::Inserter<Connection> = client
        .inserter(&std::env::var("CLICKHOUSE_TABLE").context("Reading CLICKHOUSE_TABLE")?)?
        .with_timeouts(Some(Duration::from_secs(5)), Some(Duration::from_secs(20)))
        .with_max_bytes(50_000_000)
        .with_max_rows(750_000)
        .with_period(Some(Duration::from_secs(15)));
    let inserter = Arc::new(Mutex::new(inserter));
    let blocklist = Arc::new(RwLock::new(HashMap::new()));
    #[allow(unreachable_code)]
    tokio::try_join!(
        listen_quic(endpoint, routing_table),
        listen_control(endpoint, routing_table, inserter.clone(), blocklist.clone()),
        listen_minecraft(routing_table, inserter.clone(), blocklist.clone()),
        send_commits(inserter),
        refresh_bl(blocklist)
    )?;
    Ok(())
}

async fn try_handle_quic(connection: Incoming, routing_table: &RoutingTable) -> eyre::Result<()> {
    let connection = connection.await?;
    info!(
        "QUIClime connection established to: {}",
        connection.remote_address()
    );
    let (mut send_control, mut recv_control) = connection.accept_bi().await?;
    info!("Control channel open: {}", connection.remote_address());

    let mut dialtone_ticket = None;

    let (mut handle, sender) = loop {
        let len = read_varint(&mut recv_control).await?;
        if !(0..=8192).contains(&len) {
            connection.close(VarInt::from_u32(0), &[]);
            return Ok(());
        }
        let mut buf = vec![0u8; len as usize];
        recv_control.read_exact(&mut buf).await?;
        if let Ok(parsed) = serde_json::from_slice(&buf) {
            match parsed {
                ServerboundControlMessage::ProbeCapabilities => {
                    let response =
                        serde_json::to_vec(&ClientboundControlMessage::HasCapabilities {
                            caps: vec!["dialtone_sidecar".to_string()],
                        })?;
                    send_control.write_all(&[response.len() as u8]).await?;
                    send_control.write_all(&response).await?;
                    continue;
                }
                ServerboundControlMessage::RequestDomainAssignment => {
                    let handle = routing_table.register();
                    info!(
                        "Domain assigned to {}: {}",
                        connection.remote_address(),
                        handle.0.domain()
                    );
                    let response =
                        serde_json::to_vec(&ClientboundControlMessage::DomainAssignmentComplete {
                            domain: handle.0.domain().to_string(),
                        })?;
                    send_control.write_all(&[response.len() as u8]).await?;
                    send_control.write_all(&response).await?;
                    break handle;
                }
                ServerboundControlMessage::DialtoneRegisterTicket { ticket } => {
                    dialtone_ticket = Some(ticket);
                    let response =
                        serde_json::to_vec(&ClientboundControlMessage::TicketRegistered)?;
                    send_control.write_all(&[response.len() as u8]).await?;
                    send_control.write_all(&response).await?;
                }
            }
        }
        let response = serde_json::to_vec(&ClientboundControlMessage::UnknownMessage)?;
        send_control.write_all(&[response.len() as u8]).await?;
        send_control.write_all(&response).await?;
    };

    tokio::select! {
        e = connection.closed() => {
            match e {
                ConnectionError::ConnectionClosed(_)
                | ConnectionError::ApplicationClosed(_)
                | ConnectionError::LocallyClosed => Ok(()),
                e => Err(e.into()),
            }
        },
        r = async {
            while let Some(remote) = handle.next().await {
                match remote {
                    routing::RouterRequest::RouteRequest(remote) => {
                        let pair = connection.open_bi().await;
                        if let Err(ConnectionError::ApplicationClosed(_)) = pair {
                            break;
                        } else if let Err(ConnectionError::ConnectionClosed(_)) = pair {
                            break;
                        }
                        remote.send(pair?).map_err(|e| eyre!("{:?}", e))?;
                    }
                    routing::RouterRequest::BroadcastRequest(message) => {
                        let response =
                            serde_json::to_vec(&ClientboundControlMessage::RequestMessageBroadcast {
                                message,
                            })?;
                        send_control.write_all(&[response.len() as u8]).await?;
                        send_control.write_all(&response).await?;
                    },
                    routing::RouterRequest::ServerboundControlMessage(message) => {
                        match message {
                            ServerboundControlMessage::DialtoneRegisterTicket { ticket } => {
                                info!("registering ticket {ticket:?}");
                                dialtone_ticket = Some(ticket);
                                let response = serde_json::to_vec(&ClientboundControlMessage::TicketRegistered)?;
                                send_control.write_all(&[response.len() as u8]).await?;
                                send_control.write_all(&response).await?;
                            },
                            _ => {
                                let response = serde_json::to_vec(&ClientboundControlMessage::UnknownMessage)?;
                                send_control.write_all(&[response.len() as u8]).await?;
                                send_control.write_all(&response).await?;
                            }
                        }
                    },
                    routing::RouterRequest::TicketRequest(callback) => {
                        _ = callback.send(dialtone_ticket.clone());
                    }
                }
            }
            Ok(())
        } => r,
        r = async {
            loop {
                let len = read_varint(&mut recv_control).await?;
                if !(0..=8192).contains(&len) {
                    connection.close(VarInt::from_u32(0), &[]);
                    return Ok(());
                }
                let mut buf = vec![0u8; len as usize];
                recv_control.read_exact(&mut buf).await?;
                if let Ok(parsed) = serde_json::from_slice(&buf) {
                    sender.send(RouterRequest::ServerboundControlMessage(parsed))?;
                }
            }
        } => r
    }
}

async fn handle_quic(connection: Incoming, routing_table: &RoutingTable) {
    if let Err(e) = try_handle_quic(connection, routing_table).await {
        error!("Error handling QUIClime connection: {:#}", e);
    }
    info!("Finished handling QUIClime connection");
}

async fn listen_quic(
    endpoint: &'static Endpoint,
    routing_table: &'static RoutingTable,
) -> eyre::Result<Infallible> {
    while let Some(connection) = endpoint.accept().await {
        tokio::spawn(handle_quic(connection, routing_table));
    }
    Err(eyre!("quiclime endpoint closed"))
}

async fn listen_control(
    endpoint: &'static Endpoint,
    routing_table: &'static RoutingTable,
    inserter: Arc<Mutex<Inserter<Connection>>>,
    blocklist: Arc<RwLock<HashMap<Ipv6Addr, BlocklistStatus>>>,
) -> eyre::Result<Infallible> {
    let app = axum::Router::new()
        .route(
            "/.well-known/dialtone_ticket/{domain}",
            get(
                async move |Path(addr): Path<String>, RightmostXForwardedFor(ip)| {
                    let Some(addr) = unicode_madness::validate_and_normalize_domain(&addr) else {
                        return (StatusCode::NOT_FOUND, String::new());
                    };
                    let established = OffsetDateTime::now_utc();
                    let target = addr.clone();
                    let trace = |outcome| {
                        tokio::task::spawn(async move {
                            if let Err(e) = inserter.lock().await.write(&Connection {
                                established,
                                region: routing_table.base_domain(),
                                client: match ip {
                                    std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.to_ipv6_mapped(),
                                    std::net::IpAddr::V6(ipv6_addr) => ipv6_addr,
                                },
                                intent: "dialtone",
                                outcome,
                                target,
                            }) {
                                error!("Failed to send telemetry: {e:?}");
                            }
                        });
                    };
                    if routing_table.ratelimit(ip) {
                        trace("ratelimited");
                        return (StatusCode::TOO_MANY_REQUESTS, String::new());
                    }
                    let bl_status = blocklist
                        .read()
                        .get(&match ip {
                            std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.to_ipv6_mapped(),
                            std::net::IpAddr::V6(ipv6_addr) => ipv6_addr,
                        })
                        .copied();
                    if bl_status == Some(BlocklistStatus::ShadowBanned) {
                        trace("shadowbanned");
                        return (StatusCode::NOT_FOUND, String::new());
                    } else if bl_status == Some(BlocklistStatus::Blocked) {
                        trace("blocked");
                        return (StatusCode::NOT_FOUND, String::new());
                    } else if bl_status == Some(BlocklistStatus::PingMasked) {
                        trace("ping_masked");
                        return (StatusCode::NOT_FOUND, String::new());
                    }
                    if let Some(ticket) = routing_table.check_ticket(&addr).await {
                        trace("ok");
                        (StatusCode::OK, ticket)
                    } else {
                        trace("bad_domain");
                        (StatusCode::NOT_FOUND, String::new())
                    }
                },
            ),
        )
        .route(
            "/metrics",
            get(async || format!("host_count {}\n", routing_table.size())),
        )
        .route(
            "/reload-certs",
            post(async || match create_server_config().await {
                Ok(config) => {
                    endpoint.set_server_config(Some(config));
                    (StatusCode::OK, "Success".to_string())
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
            }),
        )
        .route(
            "/broadcast",
            post(async move |body: String| routing_table.broadcast(&body)),
        )
        .route(
            "/stop",
            post(async || endpoint.close(0u32.into(), b"e4mc closing")),
        );
    let listener = tokio::net::TcpListener::bind(
        std::env::var("QUICLIME_BIND_ADDR_WEB").context("Reading QUICLIME_BIND_ADDR_WEB")?,
    )
    .await?;
    axum::serve(listener, app).await?;
    Err(eyre!("control endpoint closed"))
}

async fn try_handle_minecraft(
    mut connection: TcpStream,
    routing_table: &'static RoutingTable,
    inserter: Arc<Mutex<Inserter<Connection>>>,
    blocklist: Arc<RwLock<HashMap<Ipv6Addr, BlocklistStatus>>>,
) -> eyre::Result<()> {
    let established = OffsetDateTime::now_utc();
    let peer = connection.peer_addr()?;
    info!("Minecraft client connected from: {}", peer);
    let handshake = netty::read_packet(&mut connection, 512).await;
    if let Err(ReadError::LegacyServerListPing) = handshake {
        connection
            .write_all(include_bytes!("legacy_serverlistping_response.bin"))
            .await?;
        return Ok(());
    }
    let handshake = Handshake::new(&handshake?)?;
    let Some(address) = handshake.normalized_address() else {
        return politely_disconnect(connection, handshake).await;
    };

    let target = address.clone();
    let trace = |outcome| {
        tokio::task::spawn(async move {
            if let Err(e) = inserter.lock().await.write(&Connection {
                established,
                region: routing_table.base_domain(),
                client: match peer.ip() {
                    std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.to_ipv6_mapped(),
                    std::net::IpAddr::V6(ipv6_addr) => ipv6_addr,
                },
                intent: match handshake.next_state {
                    netty::HandshakeType::Status => "status",
                    netty::HandshakeType::Login => "login",
                },
                outcome,
                target,
            }) {
                error!("Failed to send telemetry: {e:?}");
            }
        });
    };

    if routing_table.ratelimit(peer.ip()) {
        trace("ratelimited");
        return disconnect(
            connection,
            handshake,
            include_str!("./serverlistping_response_rate.json"),
            include_str!("./disconnect_response_rate.json"),
        )
        .await;
    }
    let bl_status = blocklist
        .read()
        .get(&match peer.ip() {
            std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.to_ipv6_mapped(),
            std::net::IpAddr::V6(ipv6_addr) => ipv6_addr,
        })
        .copied();
    if bl_status == Some(BlocklistStatus::ShadowBanned) {
        trace("shadowbanned");
        return politely_disconnect(connection, handshake).await;
    } else if bl_status == Some(BlocklistStatus::Blocked) {
        trace("blocked");
        return disconnect(
            connection,
            handshake,
            include_str!("./serverlistping_response_blocked.json"),
            include_str!("./disconnect_response_blocked.json"),
        )
        .await;
    } else if bl_status == Some(BlocklistStatus::PingMasked)
        && handshake.next_state == netty::HandshakeType::Status
    {
        trace("ping_masked");
        return disconnect(
            connection,
            handshake,
            include_str!("./serverlistping_response_masked.json"),
            include_str!("./disconnect_response_blocked.json"),
        )
        .await;
    }
    let routing_result = routing_table.route(&address).await;
    let routing_ok = routing_result.is_some();
    trace(if routing_ok { "ok" } else { "bad_domain" });
    let Some((mut send_host, mut recv_host)) = routing_result else {
        return politely_disconnect(connection, handshake).await;
    };
    handshake.send(&mut send_host).await?;
    let (mut recv_client, mut send_client) = connection.split();
    tokio::select! {
        _ = tokio::io::copy(&mut recv_client, &mut send_host) => (),
        _ = tokio::io::copy(&mut recv_host, &mut send_client) => ()
    }
    _ = connection.shutdown().await;
    _ = send_host.finish();
    _ = recv_host.stop(0u32.into());
    _ = send_host.stopped().await;
    info!("Minecraft client disconnected from: {}", peer);
    Ok(())
}

async fn politely_disconnect(connection: TcpStream, handshake: Handshake) -> eyre::Result<()> {
    disconnect(
        connection,
        handshake,
        include_str!("./serverlistping_response.json"),
        include_str!("./disconnect_response.json"),
    )
    .await
}

async fn disconnect(
    mut connection: TcpStream,
    handshake: Handshake,
    slp_resp: &str,
    dc_resp: &str,
) -> eyre::Result<()> {
    match handshake.next_state {
        netty::HandshakeType::Status => {
            let packet = netty::read_packet(&mut connection, 1).await?;
            let mut packet = packet.as_slice();
            let id = packet.read_varint()?;
            if id != 0 {
                return Err(eyre!(
                    "Packet isn't a Status Request(0x00), but {:#04x}",
                    id
                ));
            }
            let mut buf = vec![];
            buf.write_varint(0).await?;
            buf.write_string(slp_resp).await?;
            connection.write_varint(buf.len() as i32).await?;
            connection.write_all(&buf).await?;
            let packet = netty::read_packet(&mut connection, 9).await?;
            let mut packet = packet.as_slice();
            let id = packet.read_varint()?;
            if id != 1 {
                return Err(eyre!("Packet isn't a Ping Request(0x01), but {:#04x}", id));
            }
            let payload = packet.read_long()?;
            let mut buf = Vec::with_capacity(1 + 8);
            buf.write_varint(1).await?;
            buf.write_u64(payload).await?;
            connection.write_varint(buf.len() as i32).await?;
            connection.write_all(&buf).await?;
        }
        netty::HandshakeType::Login => {
            let _ = netty::read_packet(&mut connection, 128).await?;
            let mut buf = vec![];
            buf.write_varint(0).await?;
            buf.write_string(dc_resp).await?;
            connection.write_varint(buf.len() as i32).await?;
            connection.write_all(&buf).await?;
        }
    }
    Ok(())
}

async fn handle_minecraft(
    connection: TcpStream,
    routing_table: &'static RoutingTable,
    inserter: Arc<Mutex<Inserter<Connection>>>,
    blocklist: Arc<RwLock<HashMap<Ipv6Addr, BlocklistStatus>>>,
) {
    if let Err(e) = try_handle_minecraft(connection, routing_table, inserter, blocklist).await {
        error!("Error handling Minecraft connection: {:#}", e);
    }
}

async fn listen_minecraft(
    routing_table: &'static RoutingTable,
    inserter: Arc<Mutex<Inserter<Connection>>>,
    blocklist: Arc<RwLock<HashMap<Ipv6Addr, BlocklistStatus>>>,
) -> eyre::Result<Infallible> {
    let server = tokio::net::TcpListener::bind(
        std::env::var("QUICLIME_BIND_ADDR_MC")
            .context("Reading QUICLIME_BIND_ADDR_MC")?
            .parse::<SocketAddr>()?,
    )
    .await?;
    loop {
        match server.accept().await {
            Ok((connection, _)) => {
                tokio::spawn(handle_minecraft(
                    connection,
                    routing_table,
                    inserter.clone(),
                    blocklist.clone(),
                ));
            }
            Err(e) => {
                error!("Error accepting minecraft connection: {:#}", e);
            }
        }
    }
}

async fn send_commits(inserter: Arc<Mutex<Inserter<Connection>>>) -> eyre::Result<Infallible> {
    loop {
        if let Err(e) = inserter.lock().await.commit().await {
            error!("Error committing: {e:?}");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
enum BlocklistStatus {
    ShadowBanned,
    Blocked,
    PingMasked,
}

async fn refresh_bl(
    blocklist: Arc<RwLock<HashMap<Ipv6Addr, BlocklistStatus>>>,
) -> eyre::Result<Infallible> {
    let client = reqwest::Client::new();
    let url = std::env::var("BLOCKLIST_URL").context("Reading BLOCKLIST_URL")?;
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let Ok(resp) = client.get(&url).send().await else {
            error!("Failed to fetch blocklist!");
            continue;
        };
        let Ok(json) = resp.json::<HashMap<Ipv6Addr, BlocklistStatus>>().await else {
            error!("Failed to fetch blocklist!");
            continue;
        };
        *blocklist.write() = json;
    }
}
