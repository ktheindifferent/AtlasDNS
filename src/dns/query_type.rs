//! DNS Query Type definitions and conversions

use serde_derive::{Deserialize, Serialize};

/// `QueryType` represents the requested Record Type of a query
///
/// The specific type Unknown that an integer parameter in order to retain the
/// id of an unknown query when compiling the reply. An integer can be converted
/// to a querytype using the `from_num` function, and back to an integer using
/// the `to_num` method.
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy, Serialize, Deserialize)]
pub enum QueryType {
    Unknown(u16),
    A,          // 1
    Ns,         // 2
    Cname,      // 5
    Soa,        // 6
    Mx,         // 15
    Txt,        // 16
    Aaaa,       // 28
    Srv,        // 33
    Opt,        // 41
    Ds,         // 43
    Rrsig,      // 46
    Nsec,       // 47
    Dnskey,     // 48
    Nsec3,      // 50
    Nsec3param, // 51
    Ixfr,       // 251
    Axfr,       // 252
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
            QueryType::Ds => 43,
            QueryType::Rrsig => 46,
            QueryType::Nsec => 47,
            QueryType::Dnskey => 48,
            QueryType::Nsec3 => 50,
            QueryType::Nsec3param => 51,
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
            43 => QueryType::Ds,
            46 => QueryType::Rrsig,
            47 => QueryType::Nsec,
            48 => QueryType::Dnskey,
            50 => QueryType::Nsec3,
            51 => QueryType::Nsec3param,
            251 => QueryType::Ixfr,
            252 => QueryType::Axfr,
            _ => QueryType::Unknown(num),
        }
    }
}