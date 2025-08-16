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
    A,     // 1
    Ns,    // 2
    Cname, // 5
    Soa,   // 6
    Mx,    // 15
    Txt,   // 16
    Aaaa,  // 28
    Srv,   // 33
    Opt,   // 41
    Axfr,  // 252
    Ixfr,  // 251
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
            QueryType::Axfr => 252,
            QueryType::Ixfr => 251,
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
            252 => QueryType::Axfr,
            251 => QueryType::Ixfr,
            _ => QueryType::Unknown(num),
        }
    }
}