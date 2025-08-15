//! EDNS0 Extensions Implementation - RFC 6891
//!
//! Extended DNS (EDNS0) support with client subnet, cookies, and other options.
//! Enables larger UDP packets, DNSSEC signaling, and enhanced functionality.
//!
//! # Features
//!
//! * **Extended UDP Size** - Support for UDP packets > 512 bytes
//! * **Client Subnet (ECS)** - RFC 7871 for CDN optimization
//! * **DNS Cookies** - RFC 7873 for amplification attack prevention
//! * **DNSSEC OK** - Signal DNSSEC awareness
//! * **TCP Keepalive** - RFC 7828 for persistent connections
//! * **Padding** - RFC 7830 for privacy protection

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode};
use crate::dns::buffer::BytePacketBuffer;
use crate::dns::errors::DnsError;

/// EDNS0 Option codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdnsOptionCode {
    /// NSID - Name Server Identifier (RFC 5001)
    Nsid = 3,
    /// DAU - DNSSEC Algorithm Understood (RFC 6975)
    Dau = 5,
    /// DHU - DS Hash Understood (RFC 6975)
    Dhu = 6,
    /// N3U - NSEC3 Hash Understood (RFC 6975)
    N3u = 7,
    /// Client Subnet (RFC 7871)
    ClientSubnet = 8,
    /// EDNS Expire (RFC 7314)
    Expire = 9,
    /// Cookie (RFC 7873)
    Cookie = 10,
    /// TCP Keepalive (RFC 7828)
    TcpKeepalive = 11,
    /// Padding (RFC 7830)
    Padding = 12,
    /// CHAIN Query (RFC 7901)
    Chain = 13,
    /// Key Tag (RFC 8145)
    KeyTag = 14,
    /// Extended DNS Error (RFC 8914)
    ExtendedDnsError = 15,
    /// Client Tag
    ClientTag = 16,
    /// Server Tag
    ServerTag = 17,
}

/// EDNS0 Option
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdnsOption {
    /// Option code
    pub code: EdnsOptionCode,
    /// Option data
    pub data: EdnsOptionData,
}

/// EDNS0 Option data variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdnsOptionData {
    /// Name Server Identifier
    Nsid(Vec<u8>),
    /// Client Subnet
    ClientSubnet(ClientSubnetOption),
    /// DNS Cookie
    Cookie(CookieOption),
    /// TCP Keepalive
    TcpKeepalive(Option<u16>),
    /// Padding
    Padding(Vec<u8>),
    /// Extended DNS Error
    ExtendedError(ExtendedErrorOption),
    /// Generic option data
    Generic(Vec<u8>),
}

/// Client Subnet Option (RFC 7871)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSubnetOption {
    /// Address family (1 = IPv4, 2 = IPv6)
    pub family: u16,
    /// Source prefix length
    pub source_prefix_len: u8,
    /// Scope prefix length
    pub scope_prefix_len: u8,
    /// Client subnet address
    pub address: IpAddr,
}

impl ClientSubnetOption {
    /// Create a new client subnet option
    pub fn new(address: IpAddr, prefix_len: u8) -> Self {
        let family = match address {
            IpAddr::V4(_) => 1,
            IpAddr::V6(_) => 2,
        };
        
        Self {
            family,
            source_prefix_len: prefix_len,
            scope_prefix_len: 0,
            address,
        }
    }

    /// Serialize to wire format
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Family
        data.extend_from_slice(&self.family.to_be_bytes());
        // Source prefix length
        data.push(self.source_prefix_len);
        // Scope prefix length
        data.push(self.scope_prefix_len);
        
        // Address (only significant bits)
        match self.address {
            IpAddr::V4(addr) => {
                let bytes = addr.octets();
                let byte_len = ((self.source_prefix_len + 7) / 8) as usize;
                data.extend_from_slice(&bytes[..byte_len]);
            }
            IpAddr::V6(addr) => {
                let bytes = addr.octets();
                let byte_len = ((self.source_prefix_len + 7) / 8) as usize;
                data.extend_from_slice(&bytes[..byte_len]);
            }
        }
        
        data
    }

    /// Parse from wire format
    pub fn parse(data: &[u8]) -> Result<Self, DnsError> {
        if data.len() < 4 {
            return Err(DnsError::Protocol(crate::dns::errors::ProtocolError {
                kind: crate::dns::errors::ProtocolErrorKind::MalformedPacket,
                packet_id: None,
                query_name: None,
                recoverable: false,
            }));
        }
        
        let family = u16::from_be_bytes([data[0], data[1]]);
        let source_prefix_len = data[2];
        let scope_prefix_len = data[3];
        
        let address = match family {
            1 => {
                // IPv4
                let byte_len = ((source_prefix_len + 7) / 8) as usize;
                let mut bytes = [0u8; 4];
                bytes[..byte_len.min(4)].copy_from_slice(&data[4..4 + byte_len.min(4)]);
                IpAddr::V4(Ipv4Addr::from(bytes))
            }
            2 => {
                // IPv6
                let byte_len = ((source_prefix_len + 7) / 8) as usize;
                let mut bytes = [0u8; 16];
                bytes[..byte_len.min(16)].copy_from_slice(&data[4..4 + byte_len.min(16)]);
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => {
                return Err(DnsError::Protocol(crate::dns::errors::ProtocolError {
                    kind: crate::dns::errors::ProtocolErrorKind::MalformedPacket,
                    packet_id: None,
                    query_name: None,
                    recoverable: false,
                }));
            }
        };
        
        Ok(Self {
            family,
            source_prefix_len,
            scope_prefix_len,
            address,
        })
    }
}

/// DNS Cookie Option (RFC 7873)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieOption {
    /// Client cookie (8 bytes)
    pub client_cookie: [u8; 8],
    /// Optional server cookie (8-32 bytes)
    pub server_cookie: Option<Vec<u8>>,
}

impl CookieOption {
    /// Create a new cookie option
    pub fn new(client_cookie: [u8; 8]) -> Self {
        Self {
            client_cookie,
            server_cookie: None,
        }
    }

    /// Generate a random client cookie
    pub fn generate_client_cookie() -> [u8; 8] {
        let mut cookie = [0u8; 8];
        for byte in &mut cookie {
            *byte = rand::random();
        }
        cookie
    }

    /// Generate server cookie based on client cookie and secret
    pub fn generate_server_cookie(client_cookie: &[u8; 8], secret: &[u8]) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(client_cookie);
        hasher.update(secret);
        hasher.update(&std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_be_bytes());
        
        hasher.finalize()[..16].to_vec()
    }
}

/// Extended DNS Error Option (RFC 8914)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedErrorOption {
    /// Error code
    pub code: u16,
    /// Extra text
    pub extra_text: Option<String>,
}

/// Extended error codes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExtendedErrorCode {
    /// Other error
    Other = 0,
    /// Unsupported DNSKEY algorithm
    UnsupportedDnskeyAlgorithm = 1,
    /// Unsupported DS digest type
    UnsupportedDsDigestType = 2,
    /// Stale answer
    StaleAnswer = 3,
    /// Forged answer
    ForgedAnswer = 4,
    /// DNSSEC indeterminate
    DnssecIndeterminate = 5,
    /// DNSSEC bogus
    DnssecBogus = 6,
    /// Signature expired
    SignatureExpired = 7,
    /// Signature not yet valid
    SignatureNotYetValid = 8,
    /// DNSKEY missing
    DnskeyMissing = 9,
    /// RRSIGs missing
    RrsigsMissing = 10,
    /// No zone key bit set
    NoZoneKeyBitSet = 11,
    /// NSEC missing
    NsecMissing = 12,
    /// Cached error
    CachedError = 13,
    /// Not ready
    NotReady = 14,
    /// Blocked
    Blocked = 15,
    /// Censored
    Censored = 16,
    /// Filtered
    Filtered = 17,
    /// Prohibited
    Prohibited = 18,
    /// Stale NX domain answer
    StaleNxDomainAnswer = 19,
    /// Not authoritative
    NotAuthoritative = 20,
    /// Not supported
    NotSupported = 21,
    /// No reachable authority
    NoReachableAuthority = 22,
    /// Network error
    NetworkError = 23,
    /// Invalid data
    InvalidData = 24,
}

/// EDNS0 record (OPT pseudo-record)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdnsRecord {
    /// Extended UDP payload size
    pub udp_size: u16,
    /// Extended RCODE (upper 8 bits)
    pub extended_rcode: u8,
    /// EDNS version
    pub version: u8,
    /// DNSSEC OK flag
    pub dnssec_ok: bool,
    /// Z field (reserved flags)
    pub z: u16,
    /// EDNS options
    pub options: Vec<EdnsOption>,
}

impl Default for EdnsRecord {
    fn default() -> Self {
        Self {
            udp_size: 4096,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: Vec::new(),
        }
    }
}

impl EdnsRecord {
    /// Create a new EDNS record
    pub fn new(udp_size: u16) -> Self {
        Self {
            udp_size,
            ..Default::default()
        }
    }

    /// Add an option
    pub fn add_option(&mut self, option: EdnsOption) {
        self.options.push(option);
    }

    /// Add client subnet option
    pub fn add_client_subnet(&mut self, address: IpAddr, prefix_len: u8) {
        self.add_option(EdnsOption {
            code: EdnsOptionCode::ClientSubnet,
            data: EdnsOptionData::ClientSubnet(ClientSubnetOption::new(address, prefix_len)),
        });
    }

    /// Add cookie option
    pub fn add_cookie(&mut self, client_cookie: [u8; 8]) {
        self.add_option(EdnsOption {
            code: EdnsOptionCode::Cookie,
            data: EdnsOptionData::Cookie(CookieOption::new(client_cookie)),
        });
    }

    /// Add padding
    pub fn add_padding(&mut self, size: usize) {
        let padding = vec![0u8; size];
        self.add_option(EdnsOption {
            code: EdnsOptionCode::Padding,
            data: EdnsOptionData::Padding(padding),
        });
    }

    /// Convert to DNS OPT record
    pub fn to_opt_record(&self) -> DnsRecord {
        // Build RDATA from options
        let mut rdata = Vec::new();
        
        for option in &self.options {
            // Option code
            let code = match option.code {
                EdnsOptionCode::Nsid => 3u16,
                EdnsOptionCode::ClientSubnet => 8,
                EdnsOptionCode::Cookie => 10,
                EdnsOptionCode::TcpKeepalive => 11,
                EdnsOptionCode::Padding => 12,
                EdnsOptionCode::ExtendedDnsError => 15,
                _ => 0,
            };
            rdata.extend_from_slice(&code.to_be_bytes());
            
            // Option data
            let data = match &option.data {
                EdnsOptionData::ClientSubnet(cs) => cs.serialize(),
                EdnsOptionData::Cookie(cookie) => {
                    let mut data = cookie.client_cookie.to_vec();
                    if let Some(server) = &cookie.server_cookie {
                        data.extend_from_slice(server);
                    }
                    data
                }
                EdnsOptionData::Padding(p) => p.clone(),
                EdnsOptionData::Generic(g) => g.clone(),
                _ => Vec::new(),
            };
            
            // Option length
            rdata.extend_from_slice(&(data.len() as u16).to_be_bytes());
            // Option data
            rdata.extend_from_slice(&data);
        }
        
        DnsRecord::Opt {
            packet_len: self.udp_size,
            flags: self.build_flags(),
            data: base64::encode(&rdata),
        }
    }

    /// Build flags field
    fn build_flags(&self) -> u32 {
        let mut flags = 0u32;
        
        // Extended RCODE (bits 24-31)
        flags |= (self.extended_rcode as u32) << 24;
        
        // Version (bits 16-23)
        flags |= (self.version as u32) << 16;
        
        // DO bit (bit 15)
        if self.dnssec_ok {
            flags |= 0x8000;
        }
        
        // Z field (bits 0-14)
        flags |= self.z as u32;
        
        flags
    }

    /// Parse from OPT record
    pub fn from_opt_record(record: &DnsRecord) -> Option<Self> {
        if let DnsRecord::Opt { packet_len, flags, data } = record {
            let data_bytes = base64::decode(data).unwrap_or_default();
            let mut edns = Self {
                udp_size: *packet_len,
                extended_rcode: ((flags >> 24) & 0xFF) as u8,
                version: ((flags >> 16) & 0xFF) as u8,
                dnssec_ok: (flags & 0x8000) != 0,
                z: (flags & 0x7FFF) as u16,
                options: Vec::new(),
            };
            
            // Parse options
            let mut offset = 0;
            while offset + 4 <= data_bytes.len() {
                let code = u16::from_be_bytes([data_bytes[offset], data_bytes[offset + 1]]);
                let len = u16::from_be_bytes([data_bytes[offset + 2], data_bytes[offset + 3]]) as usize;
                offset += 4;
                
                if offset + len > data_bytes.len() {
                    break;
                }
                
                let option_data = &data_bytes[offset..offset + len];
                offset += len;
                
                // Parse known options
                let option = match code {
                    8 => {
                        // Client Subnet
                        if let Ok(cs) = ClientSubnetOption::parse(option_data) {
                            Some(EdnsOption {
                                code: EdnsOptionCode::ClientSubnet,
                                data: EdnsOptionData::ClientSubnet(cs),
                            })
                        } else {
                            None
                        }
                    }
                    10 => {
                        // Cookie
                        if option_data.len() >= 8 {
                            let mut client_cookie = [0u8; 8];
                            client_cookie.copy_from_slice(&option_data[..8]);
                            let server_cookie = if option_data.len() > 8 {
                                Some(option_data[8..].to_vec())
                            } else {
                                None
                            };
                            Some(EdnsOption {
                                code: EdnsOptionCode::Cookie,
                                data: EdnsOptionData::Cookie(CookieOption {
                                    client_cookie,
                                    server_cookie,
                                }),
                            })
                        } else {
                            None
                        }
                    }
                    12 => {
                        // Padding
                        Some(EdnsOption {
                            code: EdnsOptionCode::Padding,
                            data: EdnsOptionData::Padding(option_data.to_vec()),
                        })
                    }
                    _ => None,
                };
                
                if let Some(opt) = option {
                    edns.options.push(opt);
                }
            }
            
            Some(edns)
        } else {
            None
        }
    }
}

/// EDNS0-aware packet processor
pub struct EdnsProcessor;

impl EdnsProcessor {
    /// Process EDNS0 in incoming packet
    pub fn process_incoming(packet: &mut DnsPacket) -> Option<EdnsRecord> {
        // Look for OPT record in additional section
        for record in &packet.resources {
            if let Some(edns) = EdnsRecord::from_opt_record(record) {
                return Some(edns);
            }
        }
        None
    }

    /// Add EDNS0 to outgoing packet
    pub fn add_to_packet(packet: &mut DnsPacket, edns: EdnsRecord) {
        packet.resources.push(edns.to_opt_record());
        packet.header.resource_entries += 1;
    }

    /// Handle client subnet option for geo-aware responses
    pub fn handle_client_subnet(
        packet: &DnsPacket,
        edns: &EdnsRecord,
    ) -> Option<IpAddr> {
        for option in &edns.options {
            if let EdnsOption {
                code: EdnsOptionCode::ClientSubnet,
                data: EdnsOptionData::ClientSubnet(cs),
            } = option
            {
                return Some(cs.address);
            }
        }
        None
    }

    /// Validate DNS cookies
    pub fn validate_cookie(
        edns: &EdnsRecord,
        server_secret: &[u8],
    ) -> bool {
        for option in &edns.options {
            if let EdnsOption {
                code: EdnsOptionCode::Cookie,
                data: EdnsOptionData::Cookie(cookie),
            } = option
            {
                if let Some(server_cookie) = &cookie.server_cookie {
                    let expected = CookieOption::generate_server_cookie(
                        &cookie.client_cookie,
                        server_secret,
                    );
                    return server_cookie == &expected;
                }
            }
        }
        false
    }
}

// Helper for rand::random
mod rand {
    pub fn random() -> u8 {
        // In production, use proper RNG
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() & 0xFF) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_client_subnet_option() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));
        let cs = ClientSubnetOption::new(addr, 24);
        
        assert_eq!(cs.family, 1);
        assert_eq!(cs.source_prefix_len, 24);
        
        let serialized = cs.serialize();
        let parsed = ClientSubnetOption::parse(&serialized).unwrap();
        
        assert_eq!(parsed.family, cs.family);
        assert_eq!(parsed.source_prefix_len, cs.source_prefix_len);
    }

    #[test]
    fn test_edns_record() {
        let mut edns = EdnsRecord::new(4096);
        edns.dnssec_ok = true;
        
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        edns.add_client_subnet(addr, 24);
        
        assert_eq!(edns.udp_size, 4096);
        assert!(edns.dnssec_ok);
        assert_eq!(edns.options.len(), 1);
    }

    #[test]
    fn test_cookie_generation() {
        let client_cookie = CookieOption::generate_client_cookie();
        assert_eq!(client_cookie.len(), 8);
        
        let server_cookie = CookieOption::generate_server_cookie(&client_cookie, b"secret");
        assert_eq!(server_cookie.len(), 16);
    }
}