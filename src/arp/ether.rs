use super::network_interface::{MacAddr, NetworkInterface};
use std::{
    mem,
    ops::{Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeFull, RangeTo},
};

/// Represents a generic network packet.
pub trait Packet {
    /// Retrieve the underlying buffer for the packet.
    fn packet(&self) -> &[u8];

    /// Retrieve the payload for the packet.
    fn payload(&self) -> &[u8];
}

/// Represents a generic, mutable, network packet.
pub trait MutablePacket: Packet {
    /// Retreive the underlying, mutable, buffer for the packet.
    fn packet_mut(&mut self) -> &mut [u8];

    /// Retreive the mutable payload for the packet.
    fn payload_mut(&mut self) -> &mut [u8];

    /// Initialize this packet by cloning another.
    fn clone_from<T: Packet>(&mut self, other: &T) {
        use std::ptr;

        assert!(self.packet().len() >= other.packet().len());
        unsafe {
            ptr::copy_nonoverlapping(
                other.packet().as_ptr(),
                self.packet_mut().as_mut_ptr(),
                other.packet().len(),
            );
        }
    }
}

/// Used to convert on-the-wire packets to their #[packet] equivalent.
pub trait FromPacket: Packet {
    /// The type of the packet to convert from.
    type T;

    /// Converts a wire-format packet to #[packet] struct format.
    fn from_packet(&self) -> Self::T;
}

/// Used to find the calculated size of the packet. This is used for occasions where the underlying
/// buffer is not the same length as the packet itself.
pub trait PacketSize: Packet {
    /// Get the calculated size of the packet.
    fn packet_size(&self) -> usize;
}

macro_rules! impl_index {
    ($t:ident, $index_t:ty, $output_t:ty) => {
        impl<'p> Index<$index_t> for $t<'p> {
            type Output = $output_t;

            fn index(&self, index: $index_t) -> &$output_t {
                &self.as_slice().index(index)
            }
        }
    };
}

macro_rules! impl_index_mut {
    ($t:ident, $index_t:ty, $output_t:ty) => {
        impl<'p> IndexMut<$index_t> for $t<'p> {
            fn index_mut(&mut self, index: $index_t) -> &mut $output_t {
                self.as_mut_slice().index_mut(index)
            }
        }
    };
}

/// Packet data.
#[derive(PartialEq)]
pub enum PacketData<'p> {
    /// A packet owns its contents.
    Owned(Vec<u8>),
    /// A packet borrows its contents.
    Borrowed(&'p [u8]),
}

impl<'p> PacketData<'p> {
    /// Get a slice of the packet data.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            &PacketData::Owned(ref data) => data.deref(),
            &PacketData::Borrowed(ref data) => data,
        }
    }

    /// No-op - returns `self`.
    pub fn to_immutable(self) -> PacketData<'p> {
        self
    }

    /// A length of the packet data.
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
}

impl_index!(PacketData, usize, u8);
impl_index!(PacketData, Range<usize>, [u8]);
impl_index!(PacketData, RangeTo<usize>, [u8]);
impl_index!(PacketData, RangeFrom<usize>, [u8]);
impl_index!(PacketData, RangeFull, [u8]);

/// Mutable packet data.
#[derive(PartialEq)]
pub enum MutPacketData<'p> {
    /// Owned mutable packet data.
    Owned(Vec<u8>),
    /// Borrowed mutable packet data.
    Borrowed(&'p mut [u8]),
}

impl<'p> MutPacketData<'p> {
    /// Get packet data as a slice.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            &MutPacketData::Owned(ref data) => data.deref(),
            &MutPacketData::Borrowed(ref data) => data,
        }
    }

    /// Get packet data as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            &mut MutPacketData::Owned(ref mut data) => data.deref_mut(),
            &mut MutPacketData::Borrowed(ref mut data) => data,
        }
    }

    /// Get an immutable version of packet data.
    pub fn to_immutable(self) -> PacketData<'p> {
        match self {
            MutPacketData::Owned(data) => PacketData::Owned(data),
            MutPacketData::Borrowed(data) => PacketData::Borrowed(data),
        }
    }

    /// Get a length of data in the packet.
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
}

impl_index!(MutPacketData, usize, u8);
impl_index!(MutPacketData, Range<usize>, [u8]);
impl_index!(MutPacketData, RangeTo<usize>, [u8]);
impl_index!(MutPacketData, RangeFrom<usize>, [u8]);
impl_index!(MutPacketData, RangeFull, [u8]);

impl_index_mut!(MutPacketData, usize, u8);
impl_index_mut!(MutPacketData, Range<usize>, [u8]);
impl_index_mut!(MutPacketData, RangeTo<usize>, [u8]);
impl_index_mut!(MutPacketData, RangeFrom<usize>, [u8]);
impl_index_mut!(MutPacketData, RangeFull, [u8]);

/// Used to convert a type to primitive values representing it.
pub trait PrimitiveValues {
    /// A tuple of types, to represent the current value.
    type T;

    /// Convert a value to primitive types representing it.
    fn to_primitive_values(&self) -> Self::T;
}

impl PrimitiveValues for MacAddr {
    type T = (u8, u8, u8, u8, u8, u8);
    fn to_primitive_values(&self) -> (u8, u8, u8, u8, u8, u8) {
        (self.0, self.1, self.2, self.3, self.4, self.5)
    }
}

impl PrimitiveValues for ::std::net::Ipv4Addr {
    type T = (u8, u8, u8, u8);
    fn to_primitive_values(&self) -> (u8, u8, u8, u8) {
        let octets = self.octets();

        (octets[0], octets[1], octets[2], octets[3])
    }
}

impl PrimitiveValues for ::std::net::Ipv6Addr {
    type T = (u16, u16, u16, u16, u16, u16, u16, u16);
    fn to_primitive_values(&self) -> (u16, u16, u16, u16, u16, u16, u16, u16) {
        let segments = self.segments();

        (
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        )
    }
}

pub struct EthernetPacket<'p> {
    packet: PacketData<'p>,
}

pub struct MutableEthernetPacket<'p> {
    packet: MutPacketData<'p>,
}

impl<'a> EthernetPacket<'a> {
    /// Constructs a new EthernetPacket. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new<'p>(packet: &'p [u8]) -> Option<EthernetPacket<'p>> {
        if packet.len() >= EthernetPacket::minimum_packet_size() {
            Some(EthernetPacket {
                packet: PacketData::Borrowed(packet),
            })
        } else {
            None
        }
    }
    /// Constructs a new EthernetPacket. If the provided buffer is less than the minimum required
    /// packet size, this will return None. With this constructor the EthernetPacket will
    /// own its own data and the underlying buffer will be dropped when the EthernetPacket is.
    pub fn owned(packet: Vec<u8>) -> Option<EthernetPacket<'static>> {
        if packet.len() >= EthernetPacket::minimum_packet_size() {
            Some(EthernetPacket {
                packet: PacketData::Owned(packet),
            })
        } else {
            None
        }
    }
    /// Maps from a EthernetPacket to a EthernetPacket
    #[inline]
    pub fn to_immutable<'p>(&'p self) -> EthernetPacket<'p> {
        EthernetPacket {
            packet: PacketData::Borrowed(self.packet.as_slice()),
        }
    }
    /// Maps from a EthernetPacket to a EthernetPacket while consuming the source
    #[inline]
    pub fn consume_to_immutable(self) -> EthernetPacket<'a> {
        EthernetPacket {
            packet: self.packet.to_immutable(),
        }
    }
    /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
    /// of the fixed-size fields.
    #[inline]
    pub const fn minimum_packet_size() -> usize {
        14
    }
    /// The size (in bytes) of a Ethernet instance when converted into
    /// a byte-array
    #[inline]
    pub fn packet_size(_packet: &Ethernet) -> usize {
        14 + _packet.payload.len()
    }
    /// Get the value of the destination field
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_destination(&self) -> MacAddr {
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg0(_self: &EthernetPacket) -> u8 {
            let co = 0;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg1(_self: &EthernetPacket) -> u8 {
            let co = 1;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg2(_self: &EthernetPacket) -> u8 {
            let co = 2;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg3(_self: &EthernetPacket) -> u8 {
            let co = 3;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg4(_self: &EthernetPacket) -> u8 {
            let co = 4;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg5(_self: &EthernetPacket) -> u8 {
            let co = 5;
            (_self.packet[co] as u8)
        }
        MacAddr::new(
            get_arg0(&self),
            get_arg1(&self),
            get_arg2(&self),
            get_arg3(&self),
            get_arg4(&self),
            get_arg5(&self),
        )
    }
    /// Get the value of the source field
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_source(&self) -> MacAddr {
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg0(_self: &EthernetPacket) -> u8 {
            let co = 6;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg1(_self: &EthernetPacket) -> u8 {
            let co = 7;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg2(_self: &EthernetPacket) -> u8 {
            let co = 8;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg3(_self: &EthernetPacket) -> u8 {
            let co = 9;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg4(_self: &EthernetPacket) -> u8 {
            let co = 10;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg5(_self: &EthernetPacket) -> u8 {
            let co = 11;
            (_self.packet[co] as u8)
        }
        MacAddr::new(
            get_arg0(&self),
            get_arg1(&self),
            get_arg2(&self),
            get_arg3(&self),
            get_arg4(&self),
            get_arg5(&self),
        )
    }
    /// Get the value of the ethertype field
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_ethertype(&self) -> EtherType {
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg0(_self: &EthernetPacket) -> u16 {
            let co = 12;
            let b0 = ((_self.packet[co + 0] as u16) << 8) as u16;
            let b1 = (_self.packet[co + 1] as u16) as u16;
            b0 | b1
        }
        EtherType::new(get_arg0(&self))
    }
}
impl<'a> MutableEthernetPacket<'a> {
    /// Constructs a new MutableEthernetPacket. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new<'p>(packet: &'p mut [u8]) -> Option<MutableEthernetPacket<'p>> {
        if packet.len() >= MutableEthernetPacket::minimum_packet_size() {
            Some(MutableEthernetPacket {
                packet: MutPacketData::Borrowed(packet),
            })
        } else {
            None
        }
    }
    /// Constructs a new MutableEthernetPacket. If the provided buffer is less than the minimum required
    /// packet size, this will return None. With this constructor the MutableEthernetPacket will
    /// own its own data and the underlying buffer will be dropped when the MutableEthernetPacket is.
    pub fn owned(packet: Vec<u8>) -> Option<MutableEthernetPacket<'static>> {
        if packet.len() >= MutableEthernetPacket::minimum_packet_size() {
            Some(MutableEthernetPacket {
                packet: MutPacketData::Owned(packet),
            })
        } else {
            None
        }
    }
    /// Maps from a MutableEthernetPacket to a EthernetPacket
    #[inline]
    pub fn to_immutable<'p>(&'p self) -> EthernetPacket<'p> {
        EthernetPacket {
            packet: PacketData::Borrowed(self.packet.as_slice()),
        }
    }
    /// Maps from a MutableEthernetPacket to a EthernetPacket while consuming the source
    #[inline]
    pub fn consume_to_immutable(self) -> EthernetPacket<'a> {
        EthernetPacket {
            packet: self.packet.to_immutable(),
        }
    }
    /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
    /// of the fixed-size fields.
    #[inline]
    pub const fn minimum_packet_size() -> usize {
        14
    }
    /// The size (in bytes) of a Ethernet instance when converted into
    /// a byte-array
    #[inline]
    pub fn packet_size(_packet: &Ethernet) -> usize {
        14 + _packet.payload.len()
    }
    /// Populates a EthernetPacket using a Ethernet structure
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn populate(&mut self, packet: &Ethernet) {
        let _self = self;
        _self.set_destination(packet.destination);
        _self.set_source(packet.source);
        _self.set_ethertype(packet.ethertype);
        _self.set_payload(&packet.payload);
    }
    /// Get the value of the destination field
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_destination(&self) -> MacAddr {
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg0(_self: &MutableEthernetPacket) -> u8 {
            let co = 0;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg1(_self: &MutableEthernetPacket) -> u8 {
            let co = 1;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg2(_self: &MutableEthernetPacket) -> u8 {
            let co = 2;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg3(_self: &MutableEthernetPacket) -> u8 {
            let co = 3;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg4(_self: &MutableEthernetPacket) -> u8 {
            let co = 4;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg5(_self: &MutableEthernetPacket) -> u8 {
            let co = 5;
            (_self.packet[co] as u8)
        }
        MacAddr::new(
            get_arg0(&self),
            get_arg1(&self),
            get_arg2(&self),
            get_arg3(&self),
            get_arg4(&self),
            get_arg5(&self),
        )
    }
    /// Get the value of the source field
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_source(&self) -> MacAddr {
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg0(_self: &MutableEthernetPacket) -> u8 {
            let co = 6;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg1(_self: &MutableEthernetPacket) -> u8 {
            let co = 7;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg2(_self: &MutableEthernetPacket) -> u8 {
            let co = 8;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg3(_self: &MutableEthernetPacket) -> u8 {
            let co = 9;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg4(_self: &MutableEthernetPacket) -> u8 {
            let co = 10;
            (_self.packet[co] as u8)
        }
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg5(_self: &MutableEthernetPacket) -> u8 {
            let co = 11;
            (_self.packet[co] as u8)
        }
        MacAddr::new(
            get_arg0(&self),
            get_arg1(&self),
            get_arg2(&self),
            get_arg3(&self),
            get_arg4(&self),
            get_arg5(&self),
        )
    }
    /// Get the value of the ethertype field
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_ethertype(&self) -> EtherType {
        #[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg0(_self: &MutableEthernetPacket) -> u16 {
            let co = 12;
            let b0 = ((_self.packet[co + 0] as u16) << 8) as u16;
            let b1 = (_self.packet[co + 1] as u16) as u16;
            b0 | b1
        }
        EtherType::new(get_arg0(&self))
    }
    /// Set the value of the destination field.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn set_destination(&mut self, val: MacAddr) {
        let _self = self;
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg0(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 0;
            _self.packet[co + 0] = (val) as u8;
        }
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg1(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 1;
            _self.packet[co + 0] = (val) as u8;
        }
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg2(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 2;
            _self.packet[co + 0] = (val) as u8;
        }
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg3(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 3;
            _self.packet[co + 0] = (val) as u8;
        }
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg4(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 4;
            _self.packet[co + 0] = (val) as u8;
        }
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg5(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 5;
            _self.packet[co + 0] = (val) as u8;
        }
        let vals = val.to_primitive_values();
        set_arg0(_self, vals.0);
        set_arg1(_self, vals.1);
        set_arg2(_self, vals.2);
        set_arg3(_self, vals.3);
        set_arg4(_self, vals.4);
        set_arg5(_self, vals.5);
    }
    /// Set the value of the source field.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn set_source(&mut self, val: MacAddr) {
        let _self = self;
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg0(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 6;
            _self.packet[co + 0] = (val) as u8;
        }
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg1(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 7;
            _self.packet[co + 0] = (val) as u8;
        }
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg2(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 8;
            _self.packet[co + 0] = (val) as u8;
        }
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg3(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 9;
            _self.packet[co + 0] = (val) as u8;
        }
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg4(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 10;
            _self.packet[co + 0] = (val) as u8;
        }
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg5(_self: &mut MutableEthernetPacket, val: u8) {
            let co = 11;
            _self.packet[co + 0] = (val) as u8;
        }
        let vals = val.to_primitive_values();
        set_arg0(_self, vals.0);
        set_arg1(_self, vals.1);
        set_arg2(_self, vals.2);
        set_arg3(_self, vals.3);
        set_arg4(_self, vals.4);
        set_arg5(_self, vals.5);
    }
    /// Set the value of the ethertype field.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn set_ethertype(&mut self, val: EtherType) {
        let _self = self;
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn set_arg0(_self: &mut MutableEthernetPacket, val: u16) {
            let co = 12;
            _self.packet[co + 0] = ((val & 65280) >> 8) as u8;
            _self.packet[co + 1] = (val) as u8;
        }
        let vals = val.to_primitive_values();
        set_arg0(_self, vals.0);
    }
    /// Set the value of the payload field (copies contents)
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn set_payload(&mut self, vals: &[u8]) {
        use std::ptr::copy_nonoverlapping;
        let mut _self = self;
        let current_offset = 14;
        unsafe {
            copy_nonoverlapping(
                vals[..].as_ptr(),
                _self.packet[current_offset..].as_mut_ptr(),
                vals.len(),
            )
        }
    }
}
impl<'a> PacketSize for EthernetPacket<'a> {
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn packet_size(&self) -> usize {
        let _self = self;
        14
    }
}
impl<'a> PacketSize for MutableEthernetPacket<'a> {
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn packet_size(&self) -> usize {
        let _self = self;
        14
    }
}
impl<'a> MutablePacket for MutableEthernetPacket<'a> {
    #[inline]
    fn packet_mut<'p>(&'p mut self) -> &'p mut [u8] {
        &mut self.packet[..]
    }
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn payload_mut<'p>(&'p mut self) -> &'p mut [u8] {
        let _self = self;
        let start = 14;
        if _self.packet.len() <= start {
            return &mut [];
        }
        &mut _self.packet[start..]
    }
}
impl<'a> Packet for MutableEthernetPacket<'a> {
    #[inline]
    fn packet<'p>(&'p self) -> &'p [u8] {
        &self.packet[..]
    }
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn payload<'p>(&'p self) -> &'p [u8] {
        let _self = self;
        let start = 14;
        if _self.packet.len() <= start {
            return &[];
        }
        &_self.packet[start..]
    }
}
impl<'a> Packet for EthernetPacket<'a> {
    #[inline]
    fn packet<'p>(&'p self) -> &'p [u8] {
        &self.packet[..]
    }
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn payload<'p>(&'p self) -> &'p [u8] {
        let _self = self;
        let start = 14;
        if _self.packet.len() <= start {
            return &[];
        }
        &_self.packet[start..]
    }
}
/// Used to iterate over a slice of `EthernetPacket`s
pub struct EthernetIterable<'a> {
    buf: &'a [u8],
}
impl<'a> Iterator for EthernetIterable<'a> {
    type Item = EthernetPacket<'a>;
    fn next(&mut self) -> Option<EthernetPacket<'a>> {
        if self.buf.len() > 0 {
            if let Some(ret) = EthernetPacket::new(self.buf) {
                let start = std::cmp::min(ret.packet_size(), self.buf.len());
                self.buf = &self.buf[start..];
                return Some(ret);
            }
        }
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}
impl<'p> FromPacket for EthernetPacket<'p> {
    type T = Ethernet;
    #[inline]
    fn from_packet(&self) -> Ethernet {
        let _self = self;
        Ethernet {
            destination: _self.get_destination(),
            source: _self.get_source(),
            ethertype: _self.get_ethertype(),
            payload: {
                let payload = self.payload();
                let mut vec = Vec::with_capacity(payload.len());
                vec.extend_from_slice(payload);
                vec
            },
        }
    }
}
impl<'p> FromPacket for MutableEthernetPacket<'p> {
    type T = Ethernet;
    #[inline]
    fn from_packet(&self) -> Ethernet {
        let _self = self;
        Ethernet {
            destination: _self.get_destination(),
            source: _self.get_source(),
            ethertype: _self.get_ethertype(),
            payload: {
                let payload = self.payload();
                let mut vec = Vec::with_capacity(payload.len());
                vec.extend_from_slice(payload);
                vec
            },
        }
    }
}
impl<'p> ::std::fmt::Debug for EthernetPacket<'p> {
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        let _self = self;
        write!(
            fmt,
            "EthernetPacket {{ destination : {:?}, source : {:?}, ethertype : {:?},  }}",
            _self.get_destination(),
            _self.get_source(),
            _self.get_ethertype()
        )
    }
}
impl<'p> ::std::fmt::Debug for MutableEthernetPacket<'p> {
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        let _self = self;
        write!(
            fmt,
            "MutableEthernetPacket {{ destination : {:?}, source : {:?}, ethertype : {:?},  }}",
            _self.get_destination(),
            _self.get_source(),
            _self.get_ethertype()
        )
    }
}

#[derive(Clone, Debug)]
#[allow(unused_attributes)]
pub struct Ethernet {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ethertype: EtherType,
    pub payload: Vec<u8>,
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod EtherTypes {
    use super::EtherType;

    // use ethernet::EtherType;
    /// Internet Protocol version 4 (IPv4) [RFC7042].
    pub const Ipv4: EtherType = EtherType(2048);
    /// Address Resolution Protocol (ARP) [RFC7042].
    pub const Arp: EtherType = EtherType(2054);
    /// Wake on Lan.
    pub const WakeOnLan: EtherType = EtherType(2114);
    /// IETF TRILL Protocol [IEEE].
    pub const Trill: EtherType = EtherType(8947);
    /// DECnet Phase IV.
    pub const DECnet: EtherType = EtherType(24579);
    /// Reverse Address Resolution Protocol (RARP) [RFC903].
    pub const Rarp: EtherType = EtherType(32821);
    /// AppleTalk - EtherTalk [Apple].
    pub const AppleTalk: EtherType = EtherType(32923);
    /// AppleTalk Address Resolution Protocol (AARP) [Apple].
    pub const Aarp: EtherType = EtherType(33011);
    /// IPX [Xerox].
    pub const Ipx: EtherType = EtherType(33079);
    /// QNX Qnet [QNX Software Systems].
    pub const Qnx: EtherType = EtherType(33284);
    /// Internet Protocol version 6 (IPv6) [RFC7042].
    pub const Ipv6: EtherType = EtherType(34525);
    /// Ethernet Flow Control [IEEE 802.3x].
    pub const FlowControl: EtherType = EtherType(34824);
    /// CobraNet [CobraNet].
    pub const CobraNet: EtherType = EtherType(34841);
    /// MPLS Unicast [RFC 3032].
    pub const Mpls: EtherType = EtherType(34887);
    /// MPLS Multicast [RFC 5332].
    pub const MplsMcast: EtherType = EtherType(34888);
    /// PPPOE Discovery Stage [RFC 2516].
    pub const PppoeDiscovery: EtherType = EtherType(34915);
    /// PPPoE Session Stage [RFC 2516].
    pub const PppoeSession: EtherType = EtherType(34916);
    /// VLAN-tagged frame (IEEE 802.1Q).
    pub const Vlan: EtherType = EtherType(33024);
    /// Provider Bridging [IEEE 802.1ad / IEEE 802.1aq].
    pub const PBridge: EtherType = EtherType(34984);
    /// Link Layer Discovery Protocol (LLDP) [IEEE 802.1AB].
    pub const Lldp: EtherType = EtherType(35020);
    /// Precision Time Protocol (PTP) over Ethernet [IEEE 1588].
    pub const Ptp: EtherType = EtherType(35063);
    /// CFM / Y.1731 [IEEE 802.1ag].
    pub const Cfm: EtherType = EtherType(35074);
    /// Q-in-Q Vlan Tagging [IEEE 802.1Q].
    pub const QinQ: EtherType = EtherType(37120);
}
/// Represents the `Ethernet::ethertype` field.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Copy)]
pub struct EtherType(pub u16);
impl EtherType {
    /// Construct a new `EtherType` instance.
    pub fn new(val: u16) -> EtherType {
        EtherType(val)
    }
}
impl PrimitiveValues for EtherType {
    type T = (u16,);
    fn to_primitive_values(&self) -> (u16,) {
        (self.0,)
    }
}
impl std::fmt::Display for EtherType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                &EtherTypes::Ipv4 => "Ipv4",
                &EtherTypes::Arp => "Arp",
                &EtherTypes::WakeOnLan => "WakeOnLan",
                &EtherTypes::Trill => "Trill",
                &EtherTypes::DECnet => "DECnet",
                &EtherTypes::Rarp => "Rarp",
                &EtherTypes::AppleTalk => "AppleTalk",
                &EtherTypes::Aarp => "Aarp",
                &EtherTypes::Ipx => "Ipx",
                &EtherTypes::Qnx => "Qnx",
                &EtherTypes::Ipv6 => "Ipv6",
                &EtherTypes::FlowControl => "FlowControl",
                &EtherTypes::CobraNet => "CobraNet",
                &EtherTypes::Mpls => "Mpls",
                &EtherTypes::MplsMcast => "MplsMcast",
                &EtherTypes::PppoeDiscovery => "PppoeDiscovery",
                &EtherTypes::PppoeSession => "PppoeSession",
                &EtherTypes::Vlan => "Vlan",
                &EtherTypes::PBridge => "PBridge",
                &EtherTypes::Lldp => "Lldp",
                &EtherTypes::Ptp => "Ptp",
                &EtherTypes::Cfm => "Cfm",
                &EtherTypes::QinQ => "QinQ",
                _ => "unknown",
            }
        )
    }
}

pub fn network_addr_to_sockaddr(
    ni: &NetworkInterface,
    storage: *mut libc::sockaddr_storage,
    proto: libc::c_int,
) -> usize {
    unsafe {
        let sll: *mut libc::sockaddr_ll = mem::transmute(storage);
        (*sll).sll_family = libc::AF_PACKET as libc::sa_family_t;
        if let Some(MacAddr(a, b, c, d, e, f)) = ni.mac {
            (*sll).sll_addr = [a, b, c, d, e, f, 0, 0];
        }
        (*sll).sll_protocol = (proto as u16).to_be();
        (*sll).sll_halen = 6;
        (*sll).sll_ifindex = ni.index as i32;
        mem::size_of::<libc::sockaddr_ll>()
    }
}
