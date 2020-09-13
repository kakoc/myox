use byteorder::{BigEndian, ByteOrder};
use std::net::{IpAddr, Ipv4Addr};

macro_rules! enum_with_unknown {
    (
        $( #[$enum_attr:meta] )*
        pub enum $name:ident($ty:ty) {
            $( $variant:ident = $value:expr ),+ $(,)*
        }
    ) => {
        enum_with_unknown! {
            $( #[$enum_attr] )*
            pub doc enum $name($ty) {
                $( #[doc(shown)] $variant = $value ),+
            }
        }
    };
    (
        $( #[$enum_attr:meta] )*
        pub doc enum $name:ident($ty:ty) {
            $(
              $( #[$variant_attr:meta] )+
              $variant:ident = $value:expr $(,)*
            ),+
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        $( #[$enum_attr] )*
        pub enum $name {
            $(
              $( #[$variant_attr] )*
              $variant
            ),*,
            Unknown($ty)
        }

        impl ::core::convert::From<$ty> for $name {
            fn from(value: $ty) -> Self {
                match value {
                    $( $value => $name::$variant ),*,
                    other => $name::Unknown(other)
                }
            }
        }

        impl ::core::convert::From<$name> for $ty {
            fn from(value: $name) -> Self {
                match value {
                    $( $name::$variant => $value ),*,
                    $name::Unknown(other) => other
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    pub buffer: T,
}

pub const HTYPE: Field = 0..2;
pub const PTYPE: Field = 2..4;
pub const HLEN: usize = 4;
pub const PLEN: usize = 5;
pub const OPER: Field = 6..8;

#[inline]
pub fn SHA(hardware_len: u8, _protocol_len: u8) -> Field {
    let start = OPER.end;
    start..(start + hardware_len as usize)
}

#[inline]
pub fn SPA(hardware_len: u8, protocol_len: u8) -> Field {
    let start = SHA(hardware_len, protocol_len).end;
    start..(start + protocol_len as usize)
}

#[inline]
pub fn THA(hardware_len: u8, protocol_len: u8) -> Field {
    let start = SPA(hardware_len, protocol_len).end;
    start..(start + hardware_len as usize)
}

#[inline]
pub fn TPA(hardware_len: u8, protocol_len: u8) -> Field {
    let start = THA(hardware_len, protocol_len).end;
    start..(start + protocol_len as usize)
}

enum_with_unknown! {
    /// Ethernet protocol type.
    pub enum Protocol(u16) {
        Ipv4 = 0x0800,
        Arp  = 0x0806,
        Ipv6 = 0x86DD
    }
}

enum_with_unknown! {
    /// ARP hardware type.
    pub enum Hardware(u16) {
        Ethernet = 1
    }
}

enum_with_unknown! {
    /// ARP operation type.
    pub enum Operation(u16) {
        Request = 1,
        Reply = 2
    }
}

pub enum Error {
    /// An operation cannot proceed because a buffer is empty or full.
    Exhausted,
    /// An operation is not permitted in the current state.
    Illegal,
    /// An endpoint or address of a remote host could not be translated to a lower level address.
    /// E.g. there was no an Ethernet address corresponding to an IPv4 address in the ARP cache,
    /// or a TCP connection attempt was made to an unspecified endpoint.
    Unaddressable,

    /// An incoming packet could not be parsed because some of its fields were out of bounds
    /// of the received data.
    Truncated,
    /// An incoming packet had an incorrect checksum and was dropped.
    Checksum,
    /// An incoming packet could not be recognized and was dropped.
    /// E.g. an Ethernet packet with an unknown EtherType.
    Unrecognized,
    /// An incoming IP packet has been split into several IP fragments and was dropped,
    /// since IP reassembly is not supported.
    Fragmented,
    /// An incoming packet was recognized but was self-contradictory.
    /// E.g. a TCP packet with both SYN and FIN flags set.
    Malformed,
    /// An incoming packet was recognized but contradicted internal state.
    /// E.g. a TCP packet addressed to a socket that doesn't exist.
    Dropped,

    #[doc(hidden)]
    __Nonexhaustive,
}

pub type Result<T> = core::result::Result<T, Error>;

pub type Field = ::core::ops::Range<usize>;

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with ARP packet structure.
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_hardware_len] or
    /// [set_protocol_len].
    ///
    /// [set_hardware_len]: #method.set_hardware_len
    /// [set_protocol_len]: #method.set_protocol_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < OPER.end {
            Err(Error::Truncated)
        } else if len < TPA(self.hardware_len(), self.protocol_len()).end {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the hardware type field.
    #[inline]
    pub fn hardware_type(&self) -> Hardware {
        let data = self.buffer.as_ref();
        let raw = BigEndian::read_u16(&data[HTYPE]);
        Hardware::from(raw)
    }

    /// Return the protocol type field.
    #[inline]
    pub fn protocol_type(&self) -> Protocol {
        let data = self.buffer.as_ref();
        let raw = BigEndian::read_u16(&data[PTYPE]);
        Protocol::from(raw)
    }

    /// Return the hardware length field.
    #[inline]
    pub fn hardware_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[HLEN]
    }

    /// Return the protocol length field.
    #[inline]
    pub fn protocol_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[PLEN]
    }

    /// Return the operation field.
    #[inline]
    pub fn operation(&self) -> Operation {
        let data = self.buffer.as_ref();
        let raw = BigEndian::read_u16(&data[OPER]);
        Operation::from(raw)
    }

    /// Return the source hardware address field.
    pub fn source_hardware_addr(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[SHA(self.hardware_len(), self.protocol_len())]
    }

    /// Return the source protocol address field.
    pub fn source_protocol_addr(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[SPA(self.hardware_len(), self.protocol_len())]
    }

    /// Return the target hardware address field.
    pub fn target_hardware_addr(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[THA(self.hardware_len(), self.protocol_len())]
    }

    /// Return the target protocol address field.
    pub fn target_protocol_addr(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[TPA(self.hardware_len(), self.protocol_len())]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the hardware type field.
    #[inline]
    pub fn set_hardware_type(&mut self, value: Hardware) {
        let data = self.buffer.as_mut();
        BigEndian::write_u16(&mut data[HTYPE], value.into())
    }

    /// Set the protocol type field.
    #[inline]
    pub fn set_protocol_type(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        BigEndian::write_u16(&mut data[PTYPE], value.into())
    }

    /// Set the hardware length field.
    #[inline]
    pub fn set_hardware_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[HLEN] = value
    }

    /// Set the protocol length field.
    #[inline]
    pub fn set_protocol_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[PLEN] = value
    }

    /// Set the operation field.
    #[inline]
    pub fn set_operation(&mut self, value: Operation) {
        let data = self.buffer.as_mut();
        BigEndian::write_u16(&mut data[OPER], value.into())
    }

    /// Set the source hardware address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.hardware_len()` long.
    pub fn set_source_hardware_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        let data = self.buffer.as_mut();
        data[SHA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// Set the source protocol address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.protocol_len()` long.
    pub fn set_source_protocol_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        let data = self.buffer.as_mut();
        data[SPA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// Set the target hardware address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.hardware_len()` long.
    pub fn set_target_hardware_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        let data = self.buffer.as_mut();
        data[THA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// Set the target protocol address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.protocol_len()` long.
    pub fn set_target_protocol_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        let data = self.buffer.as_mut();
        data[TPA(hardware_len, protocol_len)].copy_from_slice(value)
    }
}

pub fn create(mac: &[u8], ip: IpAddr) -> Option<Packet<Vec<u8>>> {
    match ip {
        IpAddr::V4(ip) => {
            // let mut bytes = vec![0xa5; 28];
            // let mut packet = Packet::new_unchecked(vec![0xa5; 28]);
            let mut packet = Packet::new_unchecked(vec![0x8; 42]);
            packet.set_hardware_type(Hardware::Ethernet);
            packet.set_protocol_type(Protocol::Ipv4);
            packet.set_hardware_len(6);
            packet.set_protocol_len(4);
            packet.set_operation(Operation::Request);
            packet.set_source_hardware_addr(mac);
            packet.set_source_protocol_addr(&ip.octets()[..]);
            packet.set_target_hardware_addr(&[0, 0, 0, 0, 0, 0]);
            packet.set_target_protocol_addr(&Ipv4Addr::new(192, 168, 0, 1).octets()[..]);

            Some(packet)
        }
        _ => {
            println!("skipped");

            None
        }
    }
}
