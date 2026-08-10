use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use data_encoding::HEXLOWER;
use iroh_base::{CustomAddr, EndpointAddr, SecretKey, TransportAddr};
use iroh_tickets::{Ticket, endpoint::EndpointTicket};
use n0_future::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use simple_dns::{
    CLASS, Name, Packet, ResourceRecord,
    rdata::{RData, TXT},
};

const MESSAGE: &str = "parity check";

#[derive(Serialize)]
struct Corpus {
    schema: &'static str,
    iroh: &'static str,
    keys: Vec<KeyVector>,
    postcard_uint: Vec<UintVector>,
    endpoint_ticket: TicketVector,
    custom_addr_tickets: Vec<CustomAddrTicketVector>,
    pkarr: PkarrVector,
}

#[derive(Serialize)]
struct KeyVector {
    seed: String,
    public: String,
    z32: String,
    message: &'static str,
    signature: String,
}

#[derive(Serialize)]
struct UintVector {
    value: u64,
    postcard: String,
}

#[derive(Serialize)]
struct TicketVector {
    encoded: String,
    bytes: String,
}

#[derive(Serialize)]
struct CustomAddrTicketVector {
    length: usize,
    encoded: String,
    bytes: String,
}

#[derive(Serialize)]
struct CustomAddrCorpus {
    custom_addr_tickets: Vec<CustomAddrTicketVector>,
}

#[derive(Deserialize)]
struct CustomAddrDecodeRequest {
    length: usize,
    encoded: String,
}

#[derive(Serialize)]
struct PkarrVector {
    bytes: String,
    name: &'static str,
    values: [&'static str; 2],
    ttl: u32,
}

#[derive(Serialize)]
struct PublishedPacket {
    key: String,
    payload: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    if let Some(command) = args.next() {
        if command == "relay-ping" {
            let url = args.next().ok_or("relay-ping requires a relay URL")?;
            if args.next().is_some() {
                return Err("relay-ping accepts one relay URL".into());
            }
            return relay_ping(&url).await;
        }
        if command == "dns-publish" {
            let addr = args.next().ok_or("dns-publish requires an HTTP address")?;
            if args.next().is_some() {
                return Err("dns-publish accepts one HTTP address".into());
            }
            return dns_publish(&addr);
        }
        if command == "transport-server" {
            let mode = args.next().ok_or("transport-server requires a mode")?;
            if args.next().is_some() {
                return Err("transport-server accepts one mode".into());
            }
            return transport_server(&mode).await;
        }
        if command == "pq-server" {
            let policy = args.next().ok_or("pq-server requires a policy")?;
            if args.next().is_some() {
                return Err("pq-server accepts one policy".into());
            }
            return pq_server(&policy).await;
        }
        if command == "pq-client" {
            let policy = args.next().ok_or("pq-client requires a policy")?;
            let id = args.next().ok_or("pq-client requires an endpoint id")?;
            let addr = args
                .next()
                .ok_or("pq-client requires an endpoint address")?;
            if args.next().is_some() {
                return Err("pq-client accepts a policy, endpoint id, and address".into());
            }
            return pq_client(&policy, &id, &addr).await;
        }
        if command == "gossip-server" {
            if args.next().is_some() {
                return Err("gossip-server accepts no arguments".into());
            }
            return gossip_server().await;
        }
        if command == "custom-addr-decode" {
            if args.next().is_some() {
                return Err("custom-addr-decode accepts no arguments".into());
            }
            return custom_addr_decode();
        }
        if command == "custom-addr-vectors" {
            if args.next().is_some() {
                return Err("custom-addr-vectors accepts no arguments".into());
            }
            let key = SecretKey::from_bytes(&[0x2a; 32]);
            serde_json::to_writer(
                std::io::stdout(),
                &CustomAddrCorpus {
                    custom_addr_tickets: custom_addr_ticket_vectors(&key),
                },
            )?;
            println!();
            return Ok(());
        }
        return Err(format!("unknown command {command}").into());
    }
    write_corpus()
}

const PQ_ALPN: &[u8] = b"go-iroh-compat/pq/1";

fn pq_provider(
    policy: &str,
) -> Result<std::sync::Arc<rustls::crypto::CryptoProvider>, Box<dyn std::error::Error>> {
    use rustls::crypto::aws_lc_rs::{self, kx_group};

    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = match policy {
        "only" => vec![kx_group::X25519MLKEM768],
        "prefer" => vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ],
        "classical" => vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1],
        _ => return Err(format!("unknown PQ policy {policy}").into()),
    };
    Ok(std::sync::Arc::new(provider))
}

fn negotiated_group(
    conn: &iroh::endpoint::Connection,
) -> Result<String, Box<dyn std::error::Error>> {
    let data = conn
        .handshake_data()
        .ok_or("Rust handshake data unavailable")?;
    let data = data
        .downcast::<noq::crypto::rustls::HandshakeData>()
        .map_err(|_| "Rust handshake data has unexpected type")?;
    Ok(format!(
        "{:?}",
        data.negotiated_key_exchange_group
            .ok_or("Rust negotiated group unavailable")?
    ))
}

async fn pq_server(policy: &str) -> Result<(), Box<dyn std::error::Error>> {
    use iroh::{Endpoint, RelayMode, endpoint::presets};

    let endpoint = Endpoint::builder(presets::Empty)
        .crypto_provider(pq_provider(policy)?)
        .alpns(vec![PQ_ALPN.to_vec()])
        .secret_key(iroh::SecretKey::from_bytes(&[0x46; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?
        .bind()
        .await?;
    let addr = endpoint
        .addr()
        .ip_addrs()
        .next()
        .copied()
        .ok_or("Rust PQ endpoint has no direct address")?;
    println!("{{\"id\":\"{}\",\"addr\":\"{}\"}}", endpoint.id(), addr);
    std::io::stdout().flush()?;
    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let conn = incoming.accept()?.await?;
    let group = negotiated_group(&conn)?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    let data = recv.read_to_end(64).await?;
    send.write_all(&data).await?;
    send.finish()?;
    println!("pq-ok group={group}");
    std::io::stdout().flush()?;
    conn.closed().await;
    endpoint.close().await;
    Ok(())
}

async fn pq_client(policy: &str, id: &str, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    use iroh::{Endpoint, RelayMode, endpoint::presets};

    let endpoint = Endpoint::builder(presets::Empty)
        .crypto_provider(pq_provider(policy)?)
        .relay_mode(RelayMode::Disabled)
        .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?
        .bind()
        .await?;
    let remote = EndpointAddr::new(id.parse()?).with_ip_addr(addr.parse()?);
    let conn = endpoint.connect(remote, PQ_ALPN).await?;
    let group = negotiated_group(&conn)?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"pq-ping").await?;
    send.finish()?;
    let echo = recv.read_to_end(64).await?;
    if echo != b"pq-ping" {
        return Err("Go PQ peer returned the wrong echo".into());
    }
    println!("pq-ok group={group}");
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    Ok(())
}

async fn gossip_server() -> Result<(), Box<dyn std::error::Error>> {
    use iroh::{Endpoint, endpoint::presets, protocol::Router};
    use iroh_gossip::{ALPN, TopicId, api::Event, net::Gossip};

    let topic = TopicId::from_bytes(*b"go-iroh rust gossip interop 001!");
    let endpoint = Endpoint::builder(presets::Minimal)
        .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, gossip.clone())
        .spawn();
    let addrs = endpoint
        .bound_sockets()
        .into_iter()
        .filter(|addr| addr.is_ipv4())
        .map(|addr| format!("\"{addr}\""))
        .collect::<Vec<_>>()
        .join(",");
    println!("{{\"id\":\"{}\",\"addrs\":[{}]}}", endpoint.id(), addrs);
    std::io::stdout().flush()?;
    let topic = gossip.subscribe(topic, Vec::new()).await?;
    let (sender, mut receiver) = topic.split();
    let mut sent = false;
    while let Some(event) = receiver.next().await {
        match event? {
            Event::Received(message) if message.content.as_ref() == b"hello from go" && !sent => {
                sender
                    .broadcast(bytes::Bytes::from_static(b"hello from rust"))
                    .await?;
                sent = true;
            }
            Event::Received(message) if message.content.as_ref() == b"gossip-ack" && sent => {
                println!("gossip-ok");
                std::io::stdout().flush()?;
                break;
            }
            Event::NeighborDown(_) | Event::Lagged | Event::NeighborUp(_) | Event::Received(_) => {}
        }
    }
    router.shutdown().await?;
    Ok(())
}

async fn transport_server(mode: &str) -> Result<(), Box<dyn std::error::Error>> {
    use iroh::{Endpoint, RelayMode, endpoint::presets};

    const ALPN: &[u8] = b"go-iroh-compat/1";
    let endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .secret_key(iroh::SecretKey::from_bytes(&[0x45; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?
        .bind()
        .await?;
    let endpoint_addr = endpoint.addr();
    let addr = endpoint_addr
        .ip_addrs()
        .next()
        .copied()
        .ok_or("Rust endpoint has no direct address")?;
    println!("{{\"id\":\"{}\",\"addr\":\"{}\"}}", endpoint.id(), addr);
    std::io::stdout().flush()?;

    if mode == "zero-rtt" {
        let mut second_was_0rtt = false;
        for round in 0..2 {
            let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
            let conn = incoming.accept()?.into_0rtt();
            let (mut send, mut recv) = conn.accept_bi().await?;
            if round == 1 {
                second_was_0rtt = recv.is_0rtt();
            }
            let data = recv.read_to_end(64).await?;
            send.write_all(&data).await?;
            send.finish()?;
            conn.closed().await;
        }
        if !second_was_0rtt {
            return Err("second Rust receive stream was not 0-RTT".into());
        }
        println!("zero-rtt-ok");
        return Ok(());
    }

    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let conn = incoming.accept()?.await?;
    match mode {
        "datagrams" => {
            let got = conn.read_datagram().await?;
            if got.as_ref() != b"go-datagram" {
                return Err("Rust peer received the wrong datagram".into());
            }
            conn.send_datagram(bytes::Bytes::from_static(b"rust-datagram"))?;
            if conn.read_datagram().await?.as_ref() != b"go-ack" {
                return Err("Rust peer received the wrong datagram acknowledgement".into());
            }
            let mut ack = conn.open_uni().await?;
            ack.write_all(b"datagrams-ok").await?;
            ack.finish()?;
            conn.closed().await;
            println!("datagrams-ok");
        }
        "close" => {
            let reason = format!("{:?}", conn.closed().await);
            if !reason.contains("ApplicationClosed")
                || !reason.contains("42")
                || !reason.contains("bye")
            {
                return Err(format!("unexpected close reason {reason}").into());
            }
            println!("close-ok");
        }
        "remote-info" => {
            let remote = conn.remote_id();
            let info = endpoint
                .remote_info(remote)
                .await
                .ok_or("Rust remote info missing")?;
            if info.id() != remote || info.addrs().next().is_none() {
                return Err("Rust remote info did not identify an address".into());
            }
            let (mut send, mut recv) = conn.accept_bi().await?;
            let data = recv.read_to_end(64).await?;
            send.write_all(&data).await?;
            send.finish()?;
            conn.closed().await;
            println!("remote-info-ok");
        }
        _ => return Err(format!("unknown transport mode {mode}").into()),
    }
    endpoint.close().await;
    Ok(())
}

fn dns_publish(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = SecretKey::from_bytes(&[0x43; 32]);
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64;
    let packet = signed_packet(
        &key,
        "_iroh",
        ["relay=https://relay.example/", "addr=127.0.0.1:4433"],
        30,
        timestamp,
    )?;
    let public = key.public().to_z32();
    let payload = &packet[32..];
    let mut stream = TcpStream::connect(addr)?;
    write!(
        stream,
        "PUT /pkarr/{public} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )?;
    stream.write_all(payload)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status = response.lines().next().unwrap_or_default();
    if !status.contains(" 204 ") {
        return Err(format!("pkarr PUT returned {status}").into());
    }
    serde_json::to_writer(
        std::io::stdout(),
        &PublishedPacket {
            key: public,
            payload: HEXLOWER.encode(payload),
        },
    )?;
    println!();
    Ok(())
}

fn write_corpus() -> Result<(), Box<dyn std::error::Error>> {
    let seeds = vec![
        "00".repeat(32),
        "2a".repeat(32),
        "ff".repeat(32),
        "0123456789abcdef".repeat(4),
    ];
    let keys = seeds
        .iter()
        .map(|seed| {
            let bytes = decode32(seed);
            let key = SecretKey::from_bytes(&bytes);
            let public = key.public();
            KeyVector {
                seed: seed.clone(),
                public: public.to_string(),
                z32: public.to_z32(),
                message: MESSAGE,
                signature: HEXLOWER.encode(&key.sign(MESSAGE.as_bytes()).to_bytes()),
            }
        })
        .collect();

    let postcard_uint = [0, 1, 127, 128, 16_383, 16_384, u32::MAX as u64, u64::MAX]
        .into_iter()
        .map(|value| UintVector {
            value,
            postcard: HEXLOWER.encode(&postcard::to_stdvec(&value).unwrap()),
        })
        .collect();

    let ticket_key = SecretKey::from_bytes(&decode32(&seeds[1]));
    let addr = EndpointAddr::new(ticket_key.public())
        .with_ip_addr(SocketAddr::from_str("127.0.0.1:4433")?)
        .with_relay_url("https://relay.example/".parse()?);
    let ticket = EndpointTicket::new(addr);
    let endpoint_ticket = TicketVector {
        encoded: ticket.encode_string(),
        bytes: HEXLOWER.encode(&ticket.encode_bytes()),
    };

    let custom_addr_tickets = custom_addr_ticket_vectors(&ticket_key);

    let pkarr_bytes = signed_packet(
        &ticket_key,
        "_iroh",
        ["relay=https://relay.example/", "addr=127.0.0.1:4433"],
        30,
        1_700_000_000_000_000,
    )?;
    iroh_dns::pkarr::SignedPacket::from_bytes(&pkarr_bytes)?;
    let pkarr = PkarrVector {
        bytes: HEXLOWER.encode(&pkarr_bytes),
        name: "_iroh",
        values: ["relay=https://relay.example/", "addr=127.0.0.1:4433"],
        ttl: 30,
    };

    let corpus = Corpus {
        schema: "go-iroh-l0/1",
        iroh: "1.0.3",
        keys,
        postcard_uint,
        endpoint_ticket,
        custom_addr_tickets,
        pkarr,
    };
    serde_json::to_writer_pretty(std::io::stdout(), &corpus)?;
    println!();
    Ok(())
}

fn custom_addr_ticket_vectors(ticket_key: &SecretKey) -> Vec<CustomAddrTicketVector> {
    [0usize, 1, 29, 30, 31, 255]
        .into_iter()
        .map(|length| {
            let data: Vec<u8> = (0..length).map(|i| i as u8).collect();
            let addr = EndpointAddr::from_parts(
                ticket_key.public(),
                [TransportAddr::Custom(CustomAddr::from_parts(42, &data))],
            );
            let ticket = EndpointTicket::new(addr);
            CustomAddrTicketVector {
                length,
                encoded: ticket.encode_string(),
                bytes: HEXLOWER.encode(&ticket.encode_bytes()),
            }
        })
        .collect()
}

fn custom_addr_decode() -> Result<(), Box<dyn std::error::Error>> {
    let requests: Vec<CustomAddrDecodeRequest> = serde_json::from_reader(std::io::stdin())?;
    let accepted: Vec<bool> = requests
        .into_iter()
        .map(|request| {
            let Ok(ticket) = EndpointTicket::decode_string(&request.encoded) else {
                return false;
            };
            let expected: Vec<u8> = (0..request.length).map(|i| i as u8).collect();
            ticket.endpoint_addr().addrs.iter().any(|addr| {
                matches!(
                    addr,
                    TransportAddr::Custom(addr)
                        if addr.id() == 42 && addr.data() == expected
                )
            })
        })
        .collect();
    serde_json::to_writer(std::io::stdout(), &accepted)?;
    println!();
    Ok(())
}

async fn relay_ping(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    use iroh_relay::protos::relay::{ClientToRelayMsg, RelayToClientMsg};

    let url: iroh_base::RelayUrl = url.parse()?;
    let key = SecretKey::from_bytes(&[0x42; 32]);
    let resolver = iroh_dns::dns::DnsResolver::new();
    let tls = iroh_relay::tls::CaTlsConfig::default()
        .client_config(iroh_relay::tls::default_provider())?;
    let client = iroh_relay::client::ClientBuilder::new(url, key, resolver)
        .tls_client_config(tls)
        .connect()
        .await?;
    let (mut stream, mut sink) = client.split();
    let ping = *b"parity42";
    sink.send(ClientToRelayMsg::Ping(ping)).await?;
    let pong = tokio::time::timeout(Duration::from_secs(3), async move {
        while let Some(message) = stream.next().await {
            if let RelayToClientMsg::Pong(value) = message? {
                return Ok::<_, Box<dyn std::error::Error>>(value);
            }
        }
        Err("relay closed without a pong".into())
    })
    .await??;
    if pong != ping {
        return Err("relay returned the wrong pong".into());
    }
    println!("relay pong");
    Ok(())
}

fn signed_packet(
    secret_key: &SecretKey,
    name: &str,
    values: [&str; 2],
    ttl: u32,
    timestamp: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let public_key = secret_key.public();
    let origin = public_key.to_z32();
    let fqdn = format!("{name}.{origin}");
    let dns_name = Name::new_unchecked(&fqdn);
    let mut packet = Packet::new_reply(0);
    for value in values {
        let mut txt = TXT::new();
        txt.add_string(value)?;
        packet.answers.push(ResourceRecord::new(
            dns_name.clone(),
            CLASS::IN,
            ttl,
            RData::TXT(txt.into_owned()),
        ));
    }
    let encoded = packet.build_bytes_vec_compressed()?;
    let mut signable = format!("3:seqi{timestamp}e1:v{}:", encoded.len()).into_bytes();
    signable.extend_from_slice(&encoded);
    let signature = secret_key.sign(&signable);
    let mut out = Vec::with_capacity(104 + encoded.len());
    out.extend_from_slice(public_key.as_bytes());
    out.extend_from_slice(&signature.to_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&encoded);
    Ok(out)
}

fn decode32(hex: &str) -> [u8; 32] {
    let decoded = HEXLOWER.decode(hex.as_bytes()).expect("valid fixture hex");
    decoded.try_into().expect("32-byte fixture")
}
