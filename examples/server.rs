#[macro_use(u32_bytes, bytes_u32)]
extern crate dhcp4r;

use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::ops::Add;

use dhcp4r::{packet, options, server};

// Server configuration
const SERVER_IP: [u8; 4] = [192, 168, 0, 76];
const IP_START: [u8; 4] = [192, 168, 0, 180];
const SUBNET_MASK: [u8; 4] = [255, 255, 255, 0];
const DNS_IPS: [u8; 8] = [8, 8, 8, 8, 8, 8, 4, 4]; // google dns servers
const ROUTER_IP: [u8; 4] = [192, 168, 0, 254];
const LEASE_DURATION_SECS: u32 = 7200;
const LEASE_NUM: u32 = 100;

// Derrived constants
const LEASE_DURATION_BYTES: [u8; 4] = u32_bytes!(LEASE_DURATION_SECS);
const IP_START_NUM: u32 = bytes_u32!(IP_START);

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:67").unwrap();
    socket.set_broadcast(true).unwrap();

    let ms = MyServer {
        leases: HashMap::new(),
        last_lease: 0,
        lease_duration: Duration::new(LEASE_DURATION_SECS as u64, 0),
    };

    server::Server::serve(socket, SERVER_IP, ms);
}

struct MyServer {
    leases: HashMap<Ipv4Addr, ([u8; 6], Instant)>,
    last_lease: u32,
    lease_duration: Duration,
}

impl server::Handler for MyServer {
    fn handle_request(&mut self,
                      server: &server::Server,
                      in_packet: packet::Packet) {
        match in_packet.message_type() {
            Ok(options::MessageType::Discover) => {
                // Prefer client's choice if available
                if let Some(r) = in_packet.option(options::REQUESTED_IP_ADDRESS) {
                    if r.len() == 4 && self.available(&in_packet.chaddr, bytes_u32!(r)) {
                        reply(server,
                              options::MessageType::Offer,
                              in_packet,
                              Ipv4Addr::from([r[0], r[1], r[2], r[3]]));
                        return;
                    }
                }
                // Otherwise prefer existing (including expired if available)
                if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                    reply(server,
                          options::MessageType::Offer,
                          in_packet,
                          ip);
                    return;
                }
                // Otherwise choose a free ip if available
                for _ in 0..LEASE_NUM {
                    self.last_lease = (self.last_lease + 1) % LEASE_NUM;
                    if self.available(&in_packet.chaddr, IP_START_NUM + &self.last_lease) {
                        reply(server,
                              options::MessageType::Offer,
                              in_packet,
                              Ipv4Addr::from(IP_START_NUM + &self.last_lease));
                        break;
                    }
                }
            }

            Ok(options::MessageType::Request) => {
                // Ignore requests to alternative DHCP server
                if !server.for_this_server(&in_packet) {
                    return;
                }
                let req_ip = match in_packet.option(options::REQUESTED_IP_ADDRESS) {
                    None => Ipv4Addr::from(in_packet.ciaddr),
                    Some(x) => {
                        if x.len() != 4 {
                            return;
                        } else {
                            Ipv4Addr::new(x[0], x[1], x[2], x[3])
                        }
                    }
                };
                if !&self.available(&in_packet.chaddr, bytes_u32!(req_ip.octets())) {
                    nak(server, in_packet, b"Requested IP not available".to_vec());
                    return;
                }
                self.leases.insert(req_ip,
                                   (in_packet.chaddr, Instant::now().add(self.lease_duration)));
                reply(server, options::MessageType::Ack, in_packet, req_ip);
            }

            Ok(options::MessageType::Release) |
            Ok(options::MessageType::Decline) => {
                // Ignore requests to alternative DHCP server
                if !server.for_this_server(&in_packet) {
                    return;
                }
                if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                    self.leases.remove(&ip);
                }
            }

            // TODO - not necessary but support for dhcp4r::INFORM might be nice
            _ => {}
        }
    }
}

impl MyServer {
    fn available(&self, chaddr: &[u8; 6], pos: u32) -> bool {
        return pos >= IP_START_NUM && pos < IP_START_NUM + LEASE_NUM &&
               match self.leases.get(&Ipv4Addr::from(pos)) {
            Some(x) => x.0 == *chaddr || Instant::now().gt(&x.1),
            None => true,
        };
    }

    fn current_lease(&self, chaddr: &[u8; 6]) -> Option<Ipv4Addr> {
        for (i, v) in &self.leases {
            if &v.0 == chaddr {
                return Some(*i);
            }
        }
        return None;
    }
}

fn reply(s: &server::Server,
         msg_type: options::MessageType,
         req_packet: packet::Packet,
         offer_ip: Ipv4Addr) {
    let _ = s.reply(msg_type,
                    vec![options::DhcpOption {
                             code: options::IP_ADDRESS_LEASE_TIME,
                             data: LEASE_DURATION_BYTES.to_vec(),
                         },
                         options::DhcpOption {
                             code: options::SUBNET_MASK,
                             data: SUBNET_MASK.to_vec(),
                         },
                         options::DhcpOption {
                             code: options::ROUTER,
                             data: ROUTER_IP.to_vec(),
                         },
                         options::DhcpOption {
                             code: options::DOMAIN_NAME_SERVER,
                             data: DNS_IPS.to_vec(),
                         }],
                    offer_ip,
                    req_packet);
}

fn nak(s: &server::Server, req_packet: packet::Packet, message: Vec<u8>) {
    let _ = s.reply(options::MessageType::Nak,
                    vec![options::DhcpOption {
                             code: options::MESSAGE,
                             data: message,
                         }],
                    Ipv4Addr::new(0, 0, 0, 0),
                    req_packet);
}
