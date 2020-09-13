use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

// use pnet::{packet::ethernet::MutableEthernetPacket, util::MacAddr};
// use smoltcp::{self, wire::ArpOperation};

// pub struct Arp {
//     hardware_type: ArpHardwareType,
//     protocol_type: EtherType,
//     hw_addr_len: u8,
//     proto_addr_len: u8,
//     operation: ArpOperation,
//     sender_hw_addr: MacAddr,
//     sender_proto_addr: Ipv4Addr,
//     target_hw_addr: MacAddr,
//     target_proto_addr: Ipv4Addr,
//     payload: Vec<u8>,
// }

pub mod arp;
pub mod arp_new;
pub mod channel;
pub mod ether;
pub mod network_interface;
pub mod other;

use arp::Packet;
use network_interface::{get_interfaces, MacAddr, NetworkInterface};

#[derive(Default)]
struct Ethernet2Frame {
    // src: [u8; 6],
    // dest: [u8; 6],
    // ethertype: [u8; 2],
    // data: [u8],
    src: Vec<u8>,
    dest: Vec<u8>,
    ethertype: Vec<u8>,
    data: Vec<u8>,
}

struct DataLink(Vec<u8>);

impl Ethernet2Frame {
    pub fn new(bytes: &[u8; 1518]) -> Self {
        let mut initial: Self = Default::default();

        let data_link = Ethernet2Frame::data_link(bytes);

        initial.src = Ethernet2Frame::src(&data_link);
        initial.dest = Ethernet2Frame::dest(&data_link);
        initial.ethertype = Ethernet2Frame::ethertype(&data_link);
        initial.data = Vec::from(&bytes[14..1514]);

        initial
    }

    pub fn data_link(bytes: &[u8]) -> DataLink {
        DataLink(bytes[..14].into())
    }

    pub fn dest(data_link: &DataLink) -> Vec<u8> {
        data_link.0[..6].into()
    }

    pub fn src(data_link: &DataLink) -> Vec<u8> {
        data_link.0[6..12].into()
    }

    pub fn ethertype(data_link: &DataLink) -> Vec<u8> {
        data_link.0[12..14].into()
    }
}

impl Display for Ethernet2Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "
dest: {:x?}
src: {:x?}
ethertype: {:x?}
data: {:x?}
\n\n\n
",
            self.dest, self.src, self.ethertype, self.data
        )
    }
}

pub fn bootstrap() {
    let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tap)
        .expect("failed to create tap");
    let mut buf = [0u8; 1518];

    // 02:42:ac:11:00:02
    // nic.send();

    // use pnet::datalink::Channel;
    // use pnet::datalink::{self, NetworkInterface};

    let interfaces = get_interfaces();
    let interfaces_name_match = |iface: &NetworkInterface| iface.name == "tun0";
    let interface = interfaces
        .into_iter()
        .filter(interfaces_name_match)
        .next()
        .unwrap();

    println!("i: {:?}", interface);

    loop {
        let nbytes = nic.recv(&mut buf[..]).unwrap();

        // match etherparse::SlicedPacket::from_ethernet(&buf[..nbytes]) {
        //     Err(value) => println!("Err {:?}", value),
        //     Ok(value) => {
        //         println!("total len: {}", nbytes);

        //         println!("link: {:?}", value.link);
        //         println!("vlan: {:?}", value.vlan);
        //         println!("ip: {:?}", value.ip);
        //         println!("transport: {:?}", value.transport);
        //         println!("\n\n");
        //     }
        // }

        let ether = Ethernet2Frame::new(&buf);
        let ethertype = u16::from_be_bytes([ether.ethertype[0], ether.ethertype[1]]);
        println!("ethertype: {:x}", ethertype);
        if ethertype == 0x0806 {
            match etherparse::SlicedPacket::from_ethernet(&buf[..nbytes]) {
                Err(value) => println!("Err {:?}", value),
                Ok(value) => {
                    println!("total len: {}", nbytes);

                    if let etherparse::LinkSlice::Ethernet2(v) = value.link.unwrap() {
                        println!("{:?}", v.to_header());
                    }

                    // println!("link: {:?}", value.link.unwrap());
                    println!("vlan: {:?}", value.vlan);
                    println!("ip: {:?}", value.ip);
                    println!("transport: {:?}", value.transport);
                    println!("\n\n");
                }
            }
        }

        if ethertype == 0x0800 {
            // let p = arp::create(&ether.src[..], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));

            other::send_arp_packet(
                interface.clone(),
                Ipv4Addr::new(192, 168, 0, 1),
                MacAddr::new(
                    ether.src[0],
                    ether.src[1],
                    ether.src[2],
                    ether.src[3],
                    ether.src[4],
                    ether.src[5],
                ),
                // config.target_ip,
                Ipv4Addr::new(172, 217, 20, 206),
                // 172.217.20.206
                // config.target_mac,
                MacAddr::new(0, 0, 0, 0, 0, 0),
                // ArpOperation::Request,
            );

            // println!("i: {:?}", p.unwrap().buffer);
            // let r = nic.send(&p.unwrap().buffer[..]);
            // let r = nic.send(&p.unwrap().buffer[..]);
            // let socket =
            //     std::net::UdpSocket::bind("192.168.0.2:2424").expect("failed to bind to address");

            // socket
            //     .send_to(&p.unwrap().buffer[..], "192.168.0.3:4242")
            //     .expect("failed to send data");
            // println!("send: {:?}", r);
        };

        // println!("{}", ether);
    }
}
