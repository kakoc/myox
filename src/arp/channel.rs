use super::{
    ether::{network_addr_to_sockaddr, EtherType, Ethernet, EthernetPacket, Packet},
    network_interface::{CSocket, NetworkInterface},
};
use std::{io, iter::repeat, mem, ptr};

pub enum Channel {
    /// A datalink channel which sends and receives Ethernet packets
    Ethernet(Box<EthernetDataLinkSender>, Box<EthernetDataLinkReceiver>),

    /// This variant should never be used
    ///
    /// Including it allows new variants to be added to `Channel` without breaking existing code.
    PleaseIncludeACatchAllVariantWhenMatchingOnThisEnum,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ChannelType {
    /// Send and receive layer 2 packets directly, including headers
    Layer2,
    /// Send and receive "cooked" packets - send and receive network layer packets
    Layer3(EtherType),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// The size of buffer to use when writing packets. Defaults to 4096
    pub write_buffer_size: usize,

    /// The size of buffer to use when reading packets. Defaults to 4096
    pub read_buffer_size: usize,

    /// The read timeout. Defaults to None.
    pub read_timeout: Option<std::time::Duration>,

    /// The write timeout. Defaults to None.
    pub write_timeout: Option<std::time::Duration>,

    /// Specifies whether to read packets at the datalink layer or network layer.
    /// NOTE FIXME Currently ignored
    /// Defaults to Layer2
    pub channel_type: ChannelType,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: None,
            write_timeout: None,
            channel_type: ChannelType::Layer2,
        }
    }
}

#[inline]
pub fn channel(network_interface: &NetworkInterface, config: Config) -> io::Result<Channel> {
    let eth_p_all = 0x0003;
    let (typ, proto) = match config.channel_type {
        Layer2 => (libc::SOCK_RAW, eth_p_all),
        ChannelType::Layer3(EtherType(proto)) => (libc::SOCK_DGRAM, proto),
    };
    let socket = unsafe { libc::socket(libc::AF_PACKET, typ, proto.to_be() as i32) };
    if socket == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = network_addr_to_sockaddr(network_interface, &mut addr, proto as i32);

    let send_addr = (&addr as *const libc::sockaddr_storage) as *const libc::sockaddr;

    // Bind to interface
    if unsafe { libc::bind(socket, send_addr, len as libc::socklen_t) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            sockets::close(socket);
        }
        return Err(err);
    }

    let mut pmr: linux::packet_mreq = unsafe { mem::zeroed() };
    pmr.mr_ifindex = network_interface.index as i32;
    pmr.mr_type = linux::PACKET_MR_PROMISC as u16;

    // Enable promiscuous capture
    if unsafe {
        libc::setsockopt(
            socket,
            linux::SOL_PACKET,
            linux::PACKET_ADD_MEMBERSHIP,
            (&pmr as *const linux::packet_mreq) as *const libc::c_void,
            mem::size_of::<linux::packet_mreq>() as u32,
        )
    } == -1
    {
        let err = io::Error::last_os_error();
        unsafe {
            sockets::close(socket);
        }
        return Err(err);
    }

    // Enable nonblocking
    if unsafe { libc::fcntl(socket, libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            sockets::close(socket);
        }
        return Err(err);
    }

    let fd = std::sync::Arc::new(FileDesc { fd: socket });
    let mut sender = Box::new(DataLinkSenderImpl {
        socket: fd.clone(),
        fd_set: unsafe { mem::zeroed() },
        write_buffer: repeat(0u8).take(config.write_buffer_size).collect(),
        _channel_type: config.channel_type,
        send_addr: unsafe { *(send_addr as *const libc::sockaddr_ll) },
        send_addr_len: len,
        timeout: config
            .write_timeout
            .map(|to| internal::duration_to_timespec(to)),
    });
    unsafe {
        libc::FD_ZERO(&mut sender.fd_set as *mut libc::fd_set);
        libc::FD_SET(fd.fd, &mut sender.fd_set as *mut libc::fd_set);
    }
    let mut receiver = Box::new(DataLinkReceiverImpl {
        socket: fd.clone(),
        fd_set: unsafe { mem::zeroed() },
        read_buffer: repeat(0u8).take(config.read_buffer_size).collect(),
        _channel_type: config.channel_type,
        timeout: config
            .read_timeout
            .map(|to| internal::duration_to_timespec(to)),
    });
    unsafe {
        libc::FD_ZERO(&mut receiver.fd_set as *mut libc::fd_set);
        libc::FD_SET(fd.fd, &mut receiver.fd_set as *mut libc::fd_set);
    }

    Ok(Channel::Ethernet(sender, receiver))
}

pub struct FileDesc {
    pub fd: CSocket,
}

impl Drop for FileDesc {
    fn drop(&mut self) {
        unsafe {
            sockets::close(self.fd);
        }
    }
}

struct DataLinkSenderImpl {
    socket: std::sync::Arc<FileDesc>,
    fd_set: libc::fd_set,
    write_buffer: Vec<u8>,
    _channel_type: ChannelType,
    send_addr: libc::sockaddr_ll,
    send_addr_len: usize,
    timeout: Option<libc::timespec>,
}

pub trait EthernetDataLinkSender: Send {
    fn send_to(
        &mut self,
        packet: &EthernetPacket,
        dst: Option<NetworkInterface>,
    ) -> Option<io::Result<()>>;
}

impl EthernetDataLinkSender for DataLinkSenderImpl {
    #[inline]
    fn send_to(
        &mut self,
        packet: &EthernetPacket,
        _dst: Option<NetworkInterface>,
    ) -> Option<io::Result<()>> {
        let ret = unsafe {
            libc::pselect(
                self.socket.fd + 1,
                ptr::null_mut(),
                &mut self.fd_set as *mut libc::fd_set,
                ptr::null_mut(),
                self.timeout
                    .as_ref()
                    .map(|to| to as *const libc::timespec)
                    .unwrap_or(ptr::null()),
                ptr::null(),
            )
        };
        if ret == -1 {
            Some(Err(io::Error::last_os_error()))
        } else if ret == 0 {
            Some(Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")))
        } else {
            match internal::send_to(
                self.socket.fd,
                packet.packet(),
                (&self.send_addr as *const libc::sockaddr_ll) as *const _,
                self.send_addr_len as libc::socklen_t,
            ) {
                Err(e) => Some(Err(e)),
                Ok(_) => Some(Ok(())),
            }
        }
    }
}

struct DataLinkReceiverImpl {
    socket: std::sync::Arc<FileDesc>,
    fd_set: libc::fd_set,
    read_buffer: Vec<u8>,
    _channel_type: ChannelType,
    timeout: Option<libc::timespec>,
}

// ($recv_name:ident, $iter_name:ident, $packet:ident) => {

pub trait EthernetDataLinkReceiver: Send {
    /// Returns an iterator over `EthernetPacket`s.
    ///
    /// This will likely be removed once other layer two types are supported.
    #[inline]
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a>;
}

/// An iterator over data link layer packets
pub trait EthernetDataLinkChannelIterator<'a> {
    /// Get the next EthernetPacket in the channel
    #[inline]
    fn next(&mut self) -> io::Result<EthernetPacket>;
}

struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
}

impl<'a> EthernetDataLinkChannelIterator<'a> for DataLinkChannelIteratorImpl<'a> {
    fn next(&mut self) -> io::Result<EthernetPacket> {
        let mut caddr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let ret = unsafe {
            libc::pselect(
                self.pc.socket.fd + 1,
                &mut self.pc.fd_set as *mut libc::fd_set,
                ptr::null_mut(),
                ptr::null_mut(),
                self.pc
                    .timeout
                    .as_ref()
                    .map(|to| to as *const libc::timespec)
                    .unwrap_or(ptr::null()),
                ptr::null(),
            )
        };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else if ret == 0 {
            Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"))
        } else {
            let res = internal::recv_from(self.pc.socket.fd, &mut self.pc.read_buffer, &mut caddr);
            match res {
                Ok(len) => Ok(EthernetPacket::new(&self.pc.read_buffer[0..len]).unwrap()),
                Err(e) => Err(e),
            }
        }
    }
}

impl EthernetDataLinkReceiver for DataLinkReceiverImpl {
    // FIXME Layer 3
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a> {
        Box::new(DataLinkChannelIteratorImpl { pc: self })
    }
}

mod internal {
    use super::sockets;
    use crate::mine::network_interface::{
        Buf, BufLen, CSocket, MutBuf, SockAddr, SockAddrStorage, SockLen,
    };
    use std::mem;

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    #[inline]
    pub fn retry<F>(f: &mut F) -> libc::ssize_t
    where
        F: FnMut() -> libc::ssize_t,
    {
        loop {
            let minus1 = -1;
            let ret = f();
            if ret != minus1 || errno() as isize != libc::EINTR as isize {
                return ret;
            }
        }
    }

    pub fn send_to(
        socket: CSocket,
        buffer: &[u8],
        dst: *const SockAddr,
        slen: SockLen,
    ) -> std::io::Result<usize> {
        let send_len = retry(&mut || unsafe {
            sockets::sendto(
                socket,
                buffer.as_ptr() as Buf,
                buffer.len() as BufLen,
                0,
                dst,
                slen,
            )
        });

        if send_len < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(send_len as usize)
        }
    }

    pub fn recv_from(
        socket: CSocket,
        buffer: &mut [u8],
        caddr: *mut SockAddrStorage,
    ) -> std::io::Result<usize> {
        let mut caddrlen = mem::size_of::<SockAddrStorage>() as SockLen;
        let len = retry(&mut || unsafe {
            sockets::recvfrom(
                socket,
                buffer.as_ptr() as MutBuf,
                buffer.len() as BufLen,
                0,
                caddr as *mut SockAddr,
                &mut caddrlen,
            )
        });

        if len < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    }

    pub fn duration_to_timespec(dur: std::time::Duration) -> libc::timespec {
        libc::timespec {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_nsec: dur.subsec_nanos() as libc::c_long,
        }
    }
}

mod sockets {
    use crate::mine::network_interface::{
        Buf, BufLen, CSocket, CouldFail, MutBuf, SockAddr, SockLen,
    };

    pub unsafe fn close(sock: CSocket) {
        let _ = libc::close(sock);
    }

    pub unsafe fn sendto(
        socket: CSocket,
        buf: Buf,
        len: BufLen,
        flags: libc::c_int,
        addr: *const SockAddr,
        addrlen: SockLen,
    ) -> CouldFail {
        libc::sendto(socket, buf, len, flags, addr, addrlen)
    }

    pub unsafe fn recvfrom(
        socket: CSocket,
        buf: MutBuf,
        len: BufLen,
        flags: libc::c_int,
        addr: *mut SockAddr,
        addrlen: *mut SockLen,
    ) -> CouldFail {
        libc::recvfrom(socket, buf, len, flags, addr, addrlen)
    }
}

mod linux {
    pub const SOL_PACKET: libc::c_int = 263;
    pub const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
    pub const PACKET_MR_PROMISC: libc::c_int = 1;

    // man 7 packet
    pub struct packet_mreq {
        pub mr_ifindex: libc::c_int,
        pub mr_type: libc::c_ushort,
        pub mr_alen: libc::c_ushort,
        pub mr_address: [libc::c_uchar; 8],
    }
}
