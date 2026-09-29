use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bao_tree::{
    BlockSize, ChunkNum, ChunkRanges,
    io::{outboard::PreOrderMemOutboard, sync::encode_ranges_validated},
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
    postcard_u8: Vec<U8Vector>,
    postcard_i8: Vec<I8Vector>,
    postcard_non_canonical: Vec<NonCanonicalVector>,
    endpoint_ticket: TicketVector,
    custom_addr_tickets: Vec<CustomAddrTicketVector>,
    ip_tickets: Vec<IpTicketVector>,
    bao: Vec<BaoVector>,
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
struct U8Vector {
    value: u8,
    postcard: String,
}

#[derive(Serialize)]
struct I8Vector {
    value: i8,
    postcard: String,
}

#[derive(Serialize)]
struct NonCanonicalVector {
    name: &'static str,
    r#type: &'static str,
    hex: &'static str,
    canonical_hex: &'static str,
    rust_accepted: bool,
}

#[derive(Deserialize)]
struct PostcardDecodeRequest {
    name: String,
    r#type: String,
    hex: String,
}

#[derive(Serialize)]
struct PostcardDecodeResult {
    name: String,
    accepted: bool,
    value: Option<String>,
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

#[derive(Deserialize)]
struct CustomAddrDecodeRequest {
    length: usize,
    encoded: String,
}

#[derive(Serialize)]
struct IpTicketVector {
    name: &'static str,
    addrs: &'static [&'static str],
    relay: Option<&'static str>,
    encoded: String,
    bytes: String,
}

#[derive(Deserialize)]
struct IpTicketDecodeRequest {
    name: String,
    encoded: String,
}

#[derive(Serialize)]
struct IpTicketDecodeResult {
    name: String,
    error: Option<String>,
    addrs: Vec<String>,
    relays: Vec<String>,
    bytes: String,
}

#[derive(Serialize)]
struct BaoVector {
    size: u64,
    name: &'static str,
    ranges: Vec<u64>,
    hash: String,
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
        if command == "blobs-get" {
            let id = args.next().ok_or("blobs-get requires an endpoint id")?;
            let addr = args
                .next()
                .ok_or("blobs-get requires an endpoint address")?;
            let root = args.next().ok_or("blobs-get requires a root hash")?;
            if args.next().is_some() {
                return Err("blobs-get accepts an endpoint id, address, and root hash".into());
            }
            return blobs_get(&id, &addr, &root).await;
        }
        if command == "gossip-server" {
            if args.next().is_some() {
                return Err("gossip-server accepts no arguments".into());
            }
            return gossip_server().await;
        }
        if command == "postcard-decode" {
            if args.next().is_some() {
                return Err("postcard-decode accepts no arguments".into());
            }
            return postcard_decode();
        }
        if command == "ip-ticket-decode" {
            if args.next().is_some() {
                return Err("ip-ticket-decode accepts no arguments".into());
            }
            return ip_ticket_decode();
        }
        if command == "custom-addr-decode" {
            if args.next().is_some() {
                return Err("custom-addr-decode accepts no arguments".into());
            }
            return custom_addr_decode();
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

/// The sizes of the blobs in the hash sequence a Go provider serves to
/// blobs-get: empty, one chunk, one chunk group, one chunk past it, and a
/// size that ends inside a chunk group. Byte i of each blob is i mod 251.
const BLOB_SIZES: [u64; 5] = [0, 1024, 16384, 17408, 100_000];

#[derive(Serialize)]
struct BlobsGetResult {
    name: &'static str,
    error: Option<String>,
}

/// blobs_get runs two get requests against a Go blobs provider serving a hash
/// sequence of BLOB_SIZES blobs at root, and prints one result per request.
/// iroh-blobs verifies every blob in each response against its hash; blobs_get
/// also checks that the response holds exactly the requested blobs, that each
/// size header is right, and that whole-blob ranges carry the blob's bytes.
async fn blobs_get(id: &str, addr: &str, root: &str) -> Result<(), Box<dyn std::error::Error>> {
    use iroh::{Endpoint, RelayMode, endpoint::presets};
    use iroh_blobs::protocol::{ChunkRangesExt, ChunkRangesSeq, GetRequest};

    let data: Vec<Vec<u8>> = BLOB_SIZES
        .iter()
        .map(|&size| (0..size).map(|i| (i % 251) as u8).collect())
        .collect();
    let hashes: Vec<iroh_blobs::Hash> = data.iter().map(iroh_blobs::Hash::new).collect();
    let root: iroh_blobs::Hash = root.parse()?;
    let seq: Vec<u8> = hashes.iter().flat_map(|h| *h.as_bytes()).collect();
    if iroh_blobs::Hash::new(&seq) != root {
        return Err("root hash is not the hash sequence of BLOB_SIZES".into());
    }

    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?
        .bind()
        .await?;
    let remote = EndpointAddr::new(id.parse()?).with_ip_addr(addr.parse()?);
    let conn = endpoint.connect(remote, iroh_blobs::ALPN).await?;

    // sendme receive asks for the whole hash sequence and the last chunk of
    // every child, which proves each child's size before any content moves.
    let sendme =
        ChunkRangesSeq::from_ranges_infinite([ChunkRanges::all(), ChunkRanges::last_chunk()]);
    // A resumed download asks only for the children it lacks.
    let per_child = ChunkRangesSeq::from_ranges([
        ChunkRanges::empty(),
        ChunkRanges::empty(),
        ChunkRanges::all(),
        ChunkRanges::empty(),
        ChunkRanges::all(),
    ]);
    let mut results = Vec::new();
    for (name, ranges) in [("sendme-all-last-chunk", sendme), ("per-child", per_child)] {
        let request = GetRequest::new(root, ranges);
        let error = blobs_get_one(&conn, request, &seq, &hashes, &data)
            .await
            .err()
            .map(|e| e.to_string());
        results.push(BlobsGetResult { name, error });
    }
    println!("{}", serde_json::to_string(&results)?);
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    Ok(())
}

async fn blobs_get_one(
    conn: &iroh::endpoint::Connection,
    request: iroh_blobs::protocol::GetRequest,
    seq: &[u8],
    hashes: &[iroh_blobs::Hash],
    data: &[Vec<u8>],
) -> Result<(), Box<dyn std::error::Error>> {
    use iroh_blobs::get::fsm::{self, ConnectedNext, EndBlobNext};

    // want lists the offsets the request selects: 0 is the root and i+1 is
    // child i.
    let want: Vec<u64> = request
        .ranges
        .iter_non_empty_infinite()
        .map(|(offset, _)| offset)
        .take_while(|&offset| offset <= hashes.len() as u64)
        .collect();
    let mut got = Vec::new();
    let connected = fsm::start(conn.clone(), request, Default::default())
        .next()
        .await?;
    let mut next = match connected.next().await? {
        ConnectedNext::StartRoot(root) => {
            let all = root.ranges().is_all();
            let (content, size) = root.next().next().await?;
            if size != seq.len() as u64 {
                return Err(format!("root size {size}, want {}", seq.len()).into());
            }
            let (end, bytes) = content.concatenate_into_vec().await?;
            if all && bytes != seq {
                return Err("root bytes differ".into());
            }
            got.push(0);
            end.next()
        }
        ConnectedNext::StartChild(child) => EndBlobNext::MoreChildren(child),
        ConnectedNext::Closing(closing) => EndBlobNext::Closing(closing),
    };
    loop {
        let child = match next {
            EndBlobNext::MoreChildren(child) => child,
            EndBlobNext::Closing(closing) => {
                closing.next().await?;
                break;
            }
        };
        let offset = child.offset();
        let Some(i) = offset
            .checked_sub(1)
            .map(|i| i as usize)
            .filter(|&i| i < hashes.len())
        else {
            child.finish().next().await?;
            break;
        };
        let all = child.ranges().is_all();
        let (content, size) = child
            .next(hashes[i])
            .next()
            .await
            .map_err(|e| format!("child {i}: {e}"))?;
        if size != data[i].len() as u64 {
            return Err(format!("child {i} size {size}, want {}", data[i].len()).into());
        }
        let (end, bytes) = content
            .concatenate_into_vec()
            .await
            .map_err(|e| format!("child {i}: {e}"))?;
        if all && bytes != data[i] {
            return Err(format!("child {i} bytes differ").into());
        }
        got.push(offset);
        next = end.next();
    }
    if got != want {
        return Err(format!("response held offsets {got:?}, want {want:?}").into());
    }
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

    // 0, 1, and 127 pin the boundary below which a varint and a raw byte
    // agree; 128, 200, and 255 are where postcard writes u8 verbatim and a
    // varint would not.
    let postcard_u8 = [0u8, 1, 127, 128, 200, 255]
        .into_iter()
        .map(|value| U8Vector {
            value,
            postcard: HEXLOWER.encode(&postcard::to_stdvec(&value).unwrap()),
        })
        .collect();

    // postcard writes i8 as two's complement, not zigzag, so the negative
    // values differ from the signed varint encoding.
    let postcard_i8 = [-128i8, -2, -1, 0, 127]
        .into_iter()
        .map(|value| I8Vector {
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
    let ip_tickets = ip_ticket_vectors(&ticket_key)?;
    let bao = bao_vectors()?;

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
        schema: "go-iroh-l0/4",
        iroh: env!("CARGO_PKG_VERSION"),
        keys,
        postcard_uint,
        postcard_u8,
        postcard_i8,
        postcard_non_canonical: non_canonical_vectors(),
        endpoint_ticket,
        custom_addr_tickets,
        ip_tickets,
        bao,
        pkarr,
    };
    serde_json::to_writer_pretty(std::io::stdout(), &corpus)?;
    println!();
    Ok(())
}

// NON_CANONICAL lists padded varint encodings: byte strings that decode to a
// value whose shortest encoding is canonical_hex. A varint is canonical when
// its final byte is non-zero, or when it is the single byte 0x00.
//
// postcard 1.1.3 accepts all of these. Its decoder accumulates seven bits per
// byte and returns as soon as the continuation bit clears, with no
// canonicality check, so go-iroh is strictly stricter here. rust_accepted is
// filled in by actually decoding, so the corpus records what upstream does
// rather than what we expect it to do.
const NON_CANONICAL: &[(&str, &str, &str, &str)] = &[
    ("overlong-300", "u64", "ac8200", "ac02"),
    ("overlong-zero", "u64", "8000", "00"),
    ("overlong-u64-padded", "u64", "81808080808080808000", "01"),
    ("overlong-slice-length", "bytes", "8100aa", "01aa"),
];

fn postcard_decode_case(kind: &str, bytes: &[u8]) -> Option<String> {
    match kind {
        "u64" => postcard::from_bytes::<u64>(bytes).ok().map(|v| v.to_string()),
        // postcard encodes a byte sequence as a varint length followed by the
        // raw bytes, so Vec<u8> reads the same wire form without a new dependency.
        "bytes" => postcard::from_bytes::<Vec<u8>>(bytes)
            .ok()
            .map(|v| HEXLOWER.encode(&v)),
        _ => None,
    }
}

fn non_canonical_vectors() -> Vec<NonCanonicalVector> {
    NON_CANONICAL
        .iter()
        .map(|(name, kind, hex, canonical_hex)| NonCanonicalVector {
            name,
            r#type: kind,
            hex,
            canonical_hex,
            // Observed, not asserted: whatever postcard does here is recorded.
            rust_accepted: postcard_decode_case(kind, &HEXLOWER.decode(hex.as_bytes()).unwrap())
                .is_some(),
        })
        .collect()
}

fn postcard_decode() -> Result<(), Box<dyn std::error::Error>> {
    let requests: Vec<PostcardDecodeRequest> = serde_json::from_reader(std::io::stdin())?;
    let results: Vec<PostcardDecodeResult> = requests
        .into_iter()
        .map(|request| {
            let value = HEXLOWER
                .decode(request.hex.as_bytes())
                .ok()
                .and_then(|bytes| postcard_decode_case(&request.r#type, &bytes));
            PostcardDecodeResult {
                name: request.name,
                accepted: value.is_some(),
                value,
            }
        })
        .collect();
    serde_json::to_writer(std::io::stdout(), &results)?;
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

// IP_TICKETS are endpoint tickets whose IP addresses exercise the SocketAddrV6
// wire form. serde writes a SocketAddrV6 as (ip, port) only, so flowinfo and
// the scope id never reach the ticket.
const IP_TICKETS: &[(&str, &[&str], Option<&str>)] = &[
    ("one-ipv6", &["[2001:db8::1]:4433"], None),
    (
        "two-ipv6",
        &["[2001:db8::1]:4433", "[2001:db8::2]:4434"],
        None,
    ),
    (
        "ipv4-and-ipv6",
        &["127.0.0.1:4433", "[2001:db8::1]:4433"],
        None,
    ),
    (
        "ipv6-and-relay",
        &["[2001:db8::1]:4433"],
        Some("https://relay.example/"),
    ),
    ("ipv4-mapped-ipv6", &["[::ffff:192.0.2.1]:4433"], None),
];

fn ip_ticket_vectors(
    ticket_key: &SecretKey,
) -> Result<Vec<IpTicketVector>, Box<dyn std::error::Error>> {
    IP_TICKETS
        .iter()
        .map(|&(name, addrs, relay)| {
            let mut addr = EndpointAddr::new(ticket_key.public());
            for a in addrs {
                addr = addr.with_ip_addr(SocketAddr::from_str(a)?);
            }
            if let Some(relay) = relay {
                addr = addr.with_relay_url(relay.parse()?);
            }
            let ticket = EndpointTicket::new(addr);
            Ok(IpTicketVector {
                name,
                addrs,
                relay,
                encoded: ticket.encode_string(),
                bytes: HEXLOWER.encode(&ticket.encode_bytes()),
            })
        })
        .collect()
}

// BAO_SIZES straddle the chunk (1024 bytes) and block (16 chunks) boundaries
// and include multi-block blobs.
const BAO_SIZES: &[u64] = &[0, 1, 1024, 1025, 16383, 16384, 16385, 100_000, 300_000];

// bao_ranges lists the chunk ranges encoded for a blob of size bytes. Every
// range except "all" selects part of a 16-chunk block, which is where an
// iroh-blobs proof descends inside the block rather than sending it whole.
fn bao_ranges(size: u64) -> Vec<(&'static str, ChunkRanges)> {
    let last = ChunkNum::chunks(size).0.saturating_sub(1);
    let mut ranges = vec![
        (
            "last-chunk",
            ChunkRanges::from(ChunkNum(last)..ChunkNum(last + 1)),
        ),
        // iroh-blobs' ChunkRanges::last_chunk: a proof of the blob's size.
        ("chunk-at-infinity", ChunkRanges::from(ChunkNum(u64::MAX)..)),
        ("mid-block", ChunkRanges::from(ChunkNum(5)..ChunkNum(7))),
        (
            "two-spans-one-block",
            ChunkRanges::from(ChunkNum(1)..ChunkNum(2))
                | ChunkRanges::from(ChunkNum(4)..ChunkNum(6)),
        ),
        (
            "crosses-block-boundary",
            ChunkRanges::from(ChunkNum(14)..ChunkNum(18)),
        ),
    ];
    // A whole multi-block blob is plain full-blob encoding, which other
    // vectors already cover, and would add hundreds of kilobytes here.
    if size <= 16_385 {
        ranges.push(("all", ChunkRanges::all()));
    }
    ranges
}

// bao_vectors encodes each range as an iroh-blobs response body: the blob
// size as a little-endian u64, then bao-tree's encoding with 16-chunk blocks.
// The blob's byte i is i % 251.
fn bao_vectors() -> Result<Vec<BaoVector>, Box<dyn std::error::Error>> {
    let mut vectors = Vec::new();
    for &size in BAO_SIZES {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let outboard = PreOrderMemOutboard::create(&data, BlockSize::from_chunk_log(4));
        for (name, ranges) in bao_ranges(size) {
            let mut encoded = size.to_le_bytes().to_vec();
            encode_ranges_validated(&data[..], &outboard, &ranges, &mut encoded)?;
            vectors.push(BaoVector {
                size,
                name,
                ranges: ranges.boundaries().iter().map(|c| c.0).collect(),
                hash: outboard.root.to_hex().to_string(),
                encoded: HEXLOWER.encode(&encoded),
            });
        }
    }
    Ok(vectors)
}

// ip_ticket_decode reads Go-encoded tickets and reports what Rust decodes from
// each, together with Rust's own re-encoding, so the caller can compare both
// the address set and the bytes.
fn ip_ticket_decode() -> Result<(), Box<dyn std::error::Error>> {
    let requests: Vec<IpTicketDecodeRequest> = serde_json::from_reader(std::io::stdin())?;
    let results: Vec<IpTicketDecodeResult> = requests
        .into_iter()
        .map(
            |request| match EndpointTicket::decode_string(&request.encoded) {
                Ok(ticket) => {
                    let addr = ticket.endpoint_addr();
                    let mut addrs: Vec<String> = addr.ip_addrs().map(|a| a.to_string()).collect();
                    addrs.sort();
                    IpTicketDecodeResult {
                        name: request.name,
                        error: None,
                        addrs,
                        relays: addr.relay_urls().map(|u| u.to_string()).collect(),
                        bytes: HEXLOWER.encode(&ticket.encode_bytes()),
                    }
                }
                Err(err) => IpTicketDecodeResult {
                    name: request.name,
                    error: Some(err.to_string()),
                    addrs: Vec::new(),
                    relays: Vec::new(),
                    bytes: String::new(),
                },
            },
        )
        .collect();
    serde_json::to_writer(std::io::stdout(), &results)?;
    println!();
    Ok(())
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
