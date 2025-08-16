//! implements the DNS protocol in a transport agnostic fashion

//use std::io::{Error, ErrorKind};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};

use derive_more::{Display, Error, From};
use rand::random;
use serde_derive::{Deserialize, Serialize};

use crate::dns::buffer::{PacketBuffer, VectorPacketBuffer};

#[derive(Debug, Display, From, Error)]
pub enum ProtocolError {
    Buffer(crate::dns::buffer::BufferError),
    Io(std::io::Error),
}

type Result<T> = std::result::Result<T, ProtocolError>;

/// `QueryType` represents the requested Record Type of a query
///
/// The specific type Unknown that an integer parameter in order to retain the
/// id of an unknown query when compiling the reply. An integer can be converted
/// to a querytype using the `from_num` function, and back to an integer using
/// the `to_num` method.
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy, Serialize, Deserialize)]
pub enum QueryType {
    Unknown(u16),
    A,     // 1
    Ns,    // 2
    Cname, // 5
    Soa,   // 6
    Mx,    // 15
    Txt,   // 16
    Aaaa,  // 28
    Srv,   // 33
    Opt,   // 41
    Ixfr,  // 251
    Axfr,  // 252
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::Unknown(x) => x,
            QueryType::A => 1,
            QueryType::Ns => 2,
            QueryType::Cname => 5,
            QueryType::Soa => 6,
            QueryType::Mx => 15,
            QueryType::Txt => 16,
            QueryType::Aaaa => 28,
            QueryType::Srv => 33,
            QueryType::Opt => 41,
            QueryType::Ixfr => 251,
            QueryType::Axfr => 252,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::Ns,
            5 => QueryType::Cname,
            6 => QueryType::Soa,
            15 => QueryType::Mx,
            16 => QueryType::Txt,
            28 => QueryType::Aaaa,
            33 => QueryType::Srv,
            41 => QueryType::Opt,
            251 => QueryType::Ixfr,
            252 => QueryType::Axfr,
            _ => QueryType::Unknown(num),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Serialize, Deserialize)]
pub struct TransientTtl(pub u32);

impl PartialEq<TransientTtl> for TransientTtl {
    fn eq(&self, _: &TransientTtl) -> bool {
        true
    }
}

impl PartialOrd<TransientTtl> for TransientTtl {
    fn partial_cmp(&self, other: &TransientTtl) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransientTtl {
    fn cmp(&self, _: &TransientTtl) -> Ordering {
        Ordering::Equal
    }
}

impl Hash for TransientTtl {
    fn hash<H>(&self, _: &mut H)
    where
        H: Hasher,
    {
        // purposely left empty
    }
}

/// `DnsRecord` is the primary representation of a DNS record
///
/// This enumeration is used for reading as well as writing records, from network
/// and from disk (for storage of authority data).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DnsRecord {
    Unknown {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: TransientTtl,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: TransientTtl,
    }, // 1
    Ns {
        domain: String,
        host: String,
        ttl: TransientTtl,
    }, // 2
    Cname {
        domain: String,
        host: String,
        ttl: TransientTtl,
    }, // 5
    Soa {
        domain: String,
        m_name: String,
        r_name: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        ttl: TransientTtl,
    }, // 6
    Mx {
        domain: String,
        priority: u16,
        host: String,
        ttl: TransientTtl,
    }, // 15
    Txt {
        domain: String,
        data: String,
        ttl: TransientTtl,
    }, // 16
    Aaaa {
        domain: String,
        addr: Ipv6Addr,
        ttl: TransientTtl,
    }, // 28
    Srv {
        domain: String,
        priority: u16,
        weight: u16,
        port: u16,
        host: String,
        ttl: TransientTtl,
    }, // 33
    Opt {
        packet_len: u16,
        flags: u32,
        data: String,
    }, // 41
}

impl DnsRecord {
    pub fn read<T: PacketBuffer>(buffer: &mut T) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let class = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain,
                    addr,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::Aaaa => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    (raw_addr1 & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    (raw_addr2 & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    (raw_addr3 & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    (raw_addr4 & 0xFFFF) as u16,
                );

                Ok(DnsRecord::Aaaa {
                    domain,
                    addr,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::Ns => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::Ns {
                    domain,
                    host: ns,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::Cname => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::Cname {
                    domain,
                    host: cname,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::Srv => {
                let priority = buffer.read_u16()?;
                let weight = buffer.read_u16()?;
                let port = buffer.read_u16()?;

                let mut srv = String::new();
                buffer.read_qname(&mut srv)?;

                Ok(DnsRecord::Srv {
                    domain,
                    priority,
                    weight,
                    port,
                    host: srv,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::Mx => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::Mx {
                    domain,
                    priority,
                    host: mx,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::Soa => {
                let mut m_name = String::new();
                buffer.read_qname(&mut m_name)?;

                let mut r_name = String::new();
                buffer.read_qname(&mut r_name)?;

                let serial = buffer.read_u32()?;
                let refresh = buffer.read_u32()?;
                let retry = buffer.read_u32()?;
                let expire = buffer.read_u32()?;
                let minimum = buffer.read_u32()?;

                Ok(DnsRecord::Soa {
                    domain,
                    m_name,
                    r_name,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::Txt => {
                let mut txt = String::new();

                let cur_pos = buffer.pos();
                txt.push_str(&String::from_utf8_lossy(
                    buffer.get_range(cur_pos, data_len as usize)?,
                ));

                buffer.step(data_len as usize)?;

                Ok(DnsRecord::Txt {
                    domain,
                    data: txt,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::Opt => {
                let mut data = String::new();

                let cur_pos = buffer.pos();
                data.push_str(&String::from_utf8_lossy(
                    buffer.get_range(cur_pos, data_len as usize)?,
                ));
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::Opt {
                    packet_len: class,
                    flags: ttl,
                    data,
                })
            }
            QueryType::Ixfr | QueryType::Axfr => {
                // Zone transfer records are handled differently
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::Unknown {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::Unknown(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::Unknown {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl: TransientTtl(ttl),
                })
            }
        }
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::Aaaa {
                ref domain,
                ref addr,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Aaaa.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::Ns {
                ref domain,
                ref host,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Ns.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::Cname {
                ref domain,
                ref host,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Cname.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::Srv {
                ref domain,
                priority,
                weight,
                port,
                ref host,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Srv.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_u16(weight)?;
                buffer.write_u16(port)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::Mx {
                ref domain,
                priority,
                ref host,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Mx.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::Soa {
                ref domain,
                ref m_name,
                ref r_name,
                serial,
                refresh,
                retry,
                expire,
                minimum,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Soa.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(m_name)?;
                buffer.write_qname(r_name)?;
                buffer.write_u32(serial)?;
                buffer.write_u32(refresh)?;
                buffer.write_u32(retry)?;
                buffer.write_u32(expire)?;
                buffer.write_u32(minimum)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::Txt {
                ref domain,
                ref data,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Txt.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(data.len() as u16)?;

                for b in data.as_bytes() {
                    buffer.write_u8(*b)?;
                }
            }
            DnsRecord::Opt { .. } => {}
            DnsRecord::Unknown { .. } => {
                log::info!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }

    pub fn get_querytype(&self) -> QueryType {
        match *self {
            DnsRecord::A { .. } => QueryType::A,
            DnsRecord::Aaaa { .. } => QueryType::Aaaa,
            DnsRecord::Ns { .. } => QueryType::Ns,
            DnsRecord::Cname { .. } => QueryType::Cname,
            DnsRecord::Srv { .. } => QueryType::Srv,
            DnsRecord::Mx { .. } => QueryType::Mx,
            DnsRecord::Unknown { qtype, .. } => QueryType::Unknown(qtype),
            DnsRecord::Soa { .. } => QueryType::Soa,
            DnsRecord::Txt { .. } => QueryType::Txt,
            DnsRecord::Opt { .. } => QueryType::Opt,
        }
    }

    pub fn get_domain(&self) -> Option<String> {
        match *self {
            DnsRecord::A { ref domain, .. }
            | DnsRecord::Aaaa { ref domain, .. }
            | DnsRecord::Ns { ref domain, .. }
            | DnsRecord::Cname { ref domain, .. }
            | DnsRecord::Srv { ref domain, .. }
            | DnsRecord::Mx { ref domain, .. }
            | DnsRecord::Unknown { ref domain, .. }
            | DnsRecord::Soa { ref domain, .. }
            | DnsRecord::Txt { ref domain, .. } => Some(domain.clone()),
            DnsRecord::Opt { .. } => None,
        }
    }

    pub fn get_ttl(&self) -> u32 {
        match *self {
            DnsRecord::A {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::Aaaa {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::Ns {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::Cname {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::Srv {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::Mx {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::Unknown {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::Soa {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::Txt {
                ttl: TransientTtl(ttl),
                ..
            } => ttl,
            DnsRecord::Opt { .. } => 0,
        }
    }
}

/// The result code for a DNS query, as described in the specification
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum ResultCode {
    #[default]
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            _ => ResultCode::NOERROR,
        }
    }
}

/// Representation of a DNS header
#[derive(Clone, Debug, Default)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7),
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }

    pub fn binary_len(&self) -> usize {
        12
    }

    pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        // Return the constant header size
        Ok(())
    }
}

impl fmt::Display for DnsHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DnsHeader:")?;
        writeln!(f, "\tid: {0}", self.id)?;

        writeln!(f, "\trecursion_desired: {0}", self.recursion_desired)?;
        writeln!(f, "\ttruncated_message: {0}", self.truncated_message)?;
        writeln!(
            f,
            "\tauthoritative_answer: {0}",
            self.authoritative_answer
        )?;
        writeln!(f, "\topcode: {0}", self.opcode)?;
        writeln!(f, "\tresponse: {0}", self.response)?;

        writeln!(f, "\trescode: {:?}", self.rescode)?;
        writeln!(f, "\tchecking_disabled: {0}", self.checking_disabled)?;
        writeln!(f, "\tauthed_data: {0}", self.authed_data)?;
        writeln!(f, "\tz: {0}", self.z)?;
        writeln!(f, "\trecursion_available: {0}", self.recursion_available)?;

        writeln!(f, "\tquestions: {0}", self.questions)?;
        writeln!(f, "\tanswers: {0}", self.answers)?;
        writeln!(
            f,
            "\tauthoritative_entries: {0}",
            self.authoritative_entries
        )?;
        writeln!(f, "\tresource_entries: {0}", self.resource_entries)?;

        Ok(())
    }
}

/// Representation of a DNS question
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name,
            qtype,
        }
    }

    pub fn binary_len(&self) -> usize {
        self.name
            .split('.')
            .map(|x| x.len() + 1)
            .fold(1, |x, y| x + y)
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }

    pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
}

impl fmt::Display for DnsQuestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DnsQuestion:")?;
        writeln!(f, "\tname: {0}", self.name)?;
        writeln!(f, "\trecord type: {:?}", self.qtype)?;

        Ok(())
    }
}

/// Representation of a complete DNS packet
///
/// This is the work horse of the server. A DNS packet can be read and written
/// in a single operation, and is used both by the network facing components and
/// internally by the resolver, cache and authority.
#[derive(Clone, Debug, Default)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer<T: PacketBuffer>(buffer: &mut T) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::Unknown(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        log::info!("{}", self.header);

        log::info!("questions:");
        for x in &self.questions {
            log::info!("\t{:?}", x);
        }

        log::info!("answers:");
        for x in &self.answers {
            log::info!("\t{:?}", x);
        }

        log::info!("authorities:");
        for x in &self.authorities {
            log::info!("\t{:?}", x);
        }

        log::info!("resources:");
        for x in &self.resources {
            log::info!("\t{:?}", x);
        }
    }

    pub fn get_ttl_from_soa(&self) -> Option<u32> {
        for answer in &self.authorities {
            if let DnsRecord::Soa { minimum, .. } = *answer {
                return Some(minimum);
            }
        }

        None
    }

    pub fn get_random_a(&self) -> Option<String> {
        if !self.answers.is_empty() {
            let idx = random::<usize>() % self.answers.len();
            let a_record = &self.answers[idx];
            if let DnsRecord::A { ref addr, .. } = *a_record {
                return Some(addr.to_string());
            }
        }

        None
    }

    pub fn get_unresolved_cnames(&self) -> Vec<DnsRecord> {
        let mut unresolved = Vec::new();
        for answer in &self.answers {
            let mut matched = false;
            if let DnsRecord::Cname { ref host, .. } = *answer {
                for answer2 in &self.answers {
                    if let DnsRecord::A { ref domain, .. } = *answer2 {
                        if domain == host {
                            matched = true;
                            break;
                        }
                    }
                }
            }

            if !matched {
                unresolved.push(answer.clone());
            }
        }

        unresolved
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<String> {
        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::Ns {
                ref domain,
                ref host,
                ..
            } = *auth
            {
                if !qname.ends_with(domain) {
                    continue;
                }

                for rsrc in &self.resources {
                    if let DnsRecord::A {
                        ref domain,
                        ref addr,
                        ttl: TransientTtl(ttl),
                    } = *rsrc
                    {
                        if domain != host {
                            continue;
                        }

                        let rec = DnsRecord::A {
                            domain: host.clone(),
                            addr: *addr,
                            ttl: TransientTtl(ttl),
                        };

                        new_authorities.push(rec);
                    }
                }
            }
        }

        if !new_authorities.is_empty() {
            let idx = random::<usize>() % new_authorities.len();
            if let DnsRecord::A { addr, .. } = new_authorities[idx] {
                return Some(addr.to_string());
            }
        }

        None
    }

    pub fn get_unresolved_ns(&self, qname: &str) -> Option<String> {
        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::Ns {
                ref domain,
                ref host,
                ..
            } = *auth
            {
                if !qname.ends_with(domain) {
                    continue;
                }

                new_authorities.push(host);
            }
        }

        if !new_authorities.is_empty() {
            let idx = random::<usize>() % new_authorities.len();
            return Some(new_authorities[idx].clone());
        }

        None
    }

    pub fn write<T: PacketBuffer>(&mut self, buffer: &mut T, max_size: usize) -> Result<()> {
        let mut test_buffer = VectorPacketBuffer::new();

        let mut size = self.header.binary_len();
        for question in &self.questions {
            size += question.binary_len();
            question.write(&mut test_buffer)?;
        }

        let mut record_count = self.answers.len() + self.authorities.len() + self.resources.len();

        for (i, rec) in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.resources.iter())
            .enumerate()
        {
            size += rec.write(&mut test_buffer)?;
            if size > max_size {
                record_count = i;
                self.header.truncated_message = true;
                break;
            } else if i < self.answers.len() {
                self.header.answers += 1;
            } else if i < self.answers.len() + self.authorities.len() {
                self.header.authoritative_entries += 1;
            } else {
                self.header.resource_entries += 1;
            }
        }

        self.header.questions = self.questions.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for rec in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.resources.iter())
            .take(record_count)
        {
            rec.write(buffer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::dns::buffer::{PacketBuffer, VectorPacketBuffer};

    #[test]
    fn test_packet() {
        let mut packet = DnsPacket::new();
        packet.header.id = 1337;
        packet.header.response = true;

        packet
            .questions
            .push(DnsQuestion::new("google.com".to_string(), QueryType::Ns));
        //packet.answers.push(DnsRecord::A("ns1.google.com".to_string(), "127.0.0.1".parse::<Ipv4Addr>().unwrap(), 3600));
        packet.answers.push(DnsRecord::Ns {
            domain: "google.com".to_string(),
            host: "ns1.google.com".to_string(),
            ttl: TransientTtl(3600),
        });
        packet.answers.push(DnsRecord::Ns {
            domain: "google.com".to_string(),
            host: "ns2.google.com".to_string(),
            ttl: TransientTtl(3600),
        });
        packet.answers.push(DnsRecord::Ns {
            domain: "google.com".to_string(),
            host: "ns3.google.com".to_string(),
            ttl: TransientTtl(3600),
        });
        packet.answers.push(DnsRecord::Ns {
            domain: "google.com".to_string(),
            host: "ns4.google.com".to_string(),
            ttl: TransientTtl(3600),
        });

        let mut buffer = VectorPacketBuffer::new();
        packet.write(&mut buffer, 0xFFFF).unwrap();

        buffer.seek(0).unwrap();

        let parsed_packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        assert_eq!(packet.questions[0], parsed_packet.questions[0]);
        assert_eq!(packet.answers[0], parsed_packet.answers[0]);
        assert_eq!(packet.answers[1], parsed_packet.answers[1]);
        assert_eq!(packet.answers[2], parsed_packet.answers[2]);
        assert_eq!(packet.answers[3], parsed_packet.answers[3]);
    }
}
