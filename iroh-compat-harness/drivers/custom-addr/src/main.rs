use data_encoding::HEXLOWER;
use iroh_base::{CustomAddr, EndpointAddr, SecretKey, TransportAddr};
use iroh_tickets::{endpoint::EndpointTicket, Ticket};
use serde::{Deserialize, Serialize};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "custom-addr-vectors" => {
            let key = SecretKey::from_bytes(&[0x2a; 32]);
            serde_json::to_writer(std::io::stdout(), &CustomAddrCorpus {
                custom_addr_tickets: custom_addr_ticket_vectors(&key),
            })?;
            println!();
            Ok(())
        }
        [command] if command == "custom-addr-decode" => custom_addr_decode(),
        _ => Err("expected custom-addr-vectors or custom-addr-decode".into()),
    }
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

