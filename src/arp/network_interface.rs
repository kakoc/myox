use super::ether::PrimitiveValues;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::os::raw::c_char;
use std::{
    ffi::{CStr, CString},
    str::from_utf8_unchecked,
};

pub type CSocket = libc::c_int;
pub type Buf = *const libc::c_void;
pub type MutBuf = *mut libc::c_void;
pub type BufLen = libc::size_t;
pub type CouldFail = libc::ssize_t;
pub type SockLen = libc::socklen_t;
pub type SockAddr = libc::sockaddr;
pub type SockAddrIn = libc::sockaddr_in;
pub type SockAddrIn6 = libc::sockaddr_in6;
pub type SockAddrStorage = libc::sockaddr_storage;
pub type SockAddrFamily = libc::sa_family_t;
pub type SockAddrFamily6 = libc::sa_family_t;
pub type InAddr = libc::in_addr;
pub type In6Addr = libc::in6_addr;

pub const AF_INET: libc::c_int = libc::AF_INET;
pub const AF_INET6: libc::c_int = libc::AF_INET6;
pub const SOCK_RAW: libc::c_int = libc::SOCK_RAW;

pub const IPPROTO_IP: libc::c_int = libc::IPPROTO_IP;
pub const IP_HDRINCL: libc::c_int = libc::IP_HDRINCL;

pub const IFF_LOOPBACK: libc::c_int = libc::IFF_LOOPBACK;

pub const INVALID_SOCKET: CSocket = -1;

#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub struct MacAddr(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddr {
    /// Construct a new MacAddr
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        MacAddr(a, b, c, d, e, f)
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            fmt,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0, self.1, self.2, self.3, self.4, self.5
        )
    }
}

impl std::fmt::Debug for MacAddr {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, fmt)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct NetworkInterface {
    /// The name of the interface
    pub name: String,
    /// The interface index (operating system specific)
    pub index: u32,
    /// A MAC address for the interface
    pub mac: Option<MacAddr>,
    /// An IP addresses for the interface
    pub ips: Option<Vec<IpAddr>>,
    /// Operating system specific flags for the interface
    pub flags: u32,
}

pub fn get_interfaces() -> Vec<NetworkInterface> {
    fn merge(old: &mut NetworkInterface, new: &NetworkInterface) {
        old.mac = match new.mac {
            None => old.mac,
            _ => new.mac,
        };
        match (&mut old.ips, &new.ips) {
            (&mut Some(ref mut old_ips), &Some(ref new_ips)) => {
                old_ips.extend_from_slice(&new_ips[..])
            }
            (&mut ref mut old_ips @ None, &Some(ref new_ips)) => *old_ips = Some(new_ips.clone()),
            _ => {}
        };
        old.flags = old.flags | new.flags;
    }

    let mut ifaces: Vec<NetworkInterface> = Vec::new();
    unsafe {
        let mut addrs: *mut libc::ifaddrs = std::mem::uninitialized();
        if libc::getifaddrs(&mut addrs) != 0 {
            return ifaces;
        }
        let mut addr = addrs;
        while !addr.is_null() {
            let c_str = (*addr).ifa_name as *const c_char;
            let bytes = CStr::from_ptr(c_str).to_bytes();
            let name = from_utf8_unchecked(bytes).to_owned();
            let (mac, ip) = sockaddr_to_network_addr((*addr).ifa_addr as *const libc::sockaddr);
            let ni = NetworkInterface {
                name: name.clone(),
                index: 0,
                mac: mac,
                ips: ip.map(|ip| [ip].to_vec()),
                flags: (*addr).ifa_flags,
            };
            let mut found: bool = false;
            for iface in &mut ifaces {
                if name == iface.name {
                    merge(iface, &ni);
                    found = true;
                }
            }
            if !found {
                ifaces.push(ni);
            }

            addr = (*addr).ifa_next;
        }
        libc::freeifaddrs(addrs);

        for iface in &mut ifaces {
            let name = CString::new(iface.name.as_bytes());
            iface.index = libc::if_nametoindex(name.unwrap().as_ptr());
        }

        ifaces
    }
}

fn sockaddr_to_network_addr(sa: *const libc::sockaddr) -> (Option<MacAddr>, Option<IpAddr>) {
    use std::mem;
    use std::net::{IpAddr, SocketAddr};

    unsafe {
        if sa.is_null() {
            (None, None)
        } else if (*sa).sa_family as libc::c_int == libc::AF_PACKET {
            let sll: *const libc::sockaddr_ll = mem::transmute(sa);
            let mac = MacAddr(
                (*sll).sll_addr[0],
                (*sll).sll_addr[1],
                (*sll).sll_addr[2],
                (*sll).sll_addr[3],
                (*sll).sll_addr[4],
                (*sll).sll_addr[5],
            );

            (Some(mac), None)
        } else {
            let addr =
                sockaddr_to_addr(mem::transmute(sa), mem::size_of::<libc::sockaddr_storage>());

            match addr {
                Ok(SocketAddr::V4(sa)) => (None, Some(IpAddr::V4(*sa.ip()))),
                Ok(SocketAddr::V6(sa)) => (None, Some(IpAddr::V6(*sa.ip()))),
                Err(_) => (None, None),
            }
        }
    }
}

pub fn sockaddr_to_addr(storage: &SockAddrStorage, len: usize) -> std::io::Result<SocketAddr> {
    use std::mem;

    match storage.ss_family as libc::c_int {
        AF_INET => {
            assert!(len as usize >= mem::size_of::<SockAddrIn>());
            let storage: &SockAddrIn = unsafe { mem::transmute(storage) };
            let ip = ipv4_addr(storage.sin_addr);
            let a = (ip >> 24) as u8;
            let b = (ip >> 16) as u8;
            let c = (ip >> 8) as u8;
            let d = ip as u8;
            let sockaddrv4 = SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), ntohs(storage.sin_port));
            Ok(SocketAddr::V4(sockaddrv4))
        }
        // AF_INET6 => {
        //     assert!(len as usize >= mem::size_of::<sockets::SockAddrIn6>());
        //     let storage: &sockets::SockAddrIn6 = unsafe { mem::transmute(storage) };
        //     let arr: [u16; 8] = unsafe { mem::transmute(storage.sin6_addr.s6_addr) };
        //     let a = ntohs(arr[0]);
        //     let b = ntohs(arr[1]);
        //     let c = ntohs(arr[2]);
        //     let d = ntohs(arr[3]);
        //     let e = ntohs(arr[4]);
        //     let f = ntohs(arr[5]);
        //     let g = ntohs(arr[6]);
        //     let h = ntohs(arr[7]);
        //     let ip = Ipv6Addr::new(a, b, c, d, e, f, g, h);
        //     Ok(SocketAddr::V6(SocketAddrV6::new(
        //         ip,
        //         ntohs(storage.sin6_port),
        //         u32::from_be(storage.sin6_flowinfo),
        //         u32::from_be(storage.sin6_scope_id),
        //     )))
        // }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected IPv4 or IPv6 socket",
        )),
    }
}

fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

#[inline(always)]
pub fn ipv4_addr(addr: InAddr) -> u32 {
    (addr.s_addr as u32).to_be()
}
