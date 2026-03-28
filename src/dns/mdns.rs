#![allow(dead_code)]
//! Passive mDNS (Multicast DNS, RFC 6762) listener for local device discovery.
//!
//! Joins the link-local multicast group `224.0.0.251:5353` and silently
//! observes mDNS traffic to build a registry of `.local` hostnames, their IP
//! addresses, and any advertised service types (_http._tcp, _ssh._tcp, …).
//!
//! The registry is safe to query from any thread via [`MdnsRegistry`].

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// mDNS all-nodes multicast address.
pub const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// Well-known mDNS / DNS-SD port.
pub const MDNS_PORT: u16 = 5353;

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

/// A device discovered on the local network via mDNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsDevice {
    /// Bare hostname without the `.local` suffix.
    pub hostname: String,
    /// IP address (IPv4 or IPv6 as a string), if seen.
    pub ip: Option<String>,
    /// Service types advertised by the device, e.g. `["_http._tcp", "_ssh._tcp"]`.
    pub services: Vec<String>,
    /// Unix-epoch seconds of the most recent observation.
    pub last_seen: u64,
}

/// Thread-safe registry of mDNS-discovered devices.
pub struct MdnsRegistry {
    devices: RwLock<HashMap<String, MdnsDevice>>,
}

impl Default for MdnsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MdnsRegistry {
    pub fn new() -> Self {
        MdnsRegistry {
            devices: RwLock::new(HashMap::new()),
        }
    }

    /// Insert or refresh a device entry.
    pub fn upsert(&self, hostname: &str, ip: Option<String>, service: Option<String>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut guard = self.devices.write().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(hostname.to_string()).or_insert_with(|| MdnsDevice {
            hostname: hostname.to_string(),
            ip: None,
            services: Vec::new(),
            last_seen: now,
        });
        entry.last_seen = now;
        if let Some(addr) = ip {
            entry.ip = Some(addr);
        }
        if let Some(svc) = service {
            if !entry.services.contains(&svc) {
                entry.services.push(svc);
            }
        }
    }

    /// Look up the IP address for a bare hostname (without `.local`).
    pub fn lookup_ip(&self, hostname: &str) -> Option<String> {
        self.devices
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(hostname)
            .and_then(|d| d.ip.clone())
    }

    /// Return a snapshot of all known devices.
    pub fn all_devices(&self) -> Vec<MdnsDevice> {
        self.devices
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Minimal DNS-wire-format parser (independent of the 512-byte BytePacketBuffer)
// ---------------------------------------------------------------------------

/// Parse a DNS-compressed name from `data` starting at `*pos`.
/// Advances `*pos` to the byte after the name (or after the compression pointer).
fn read_name(data: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut return_pos: usize = 0;
    let mut hops = 0usize;

    loop {
        if *pos >= data.len() {
            return None;
        }
        let byte = data[*pos];

        // Compression pointer: top two bits set
        if byte & 0xC0 == 0xC0 {
            if *pos + 1 >= data.len() {
                return None;
            }
            let offset = (((byte & 0x3F) as usize) << 8) | (data[*pos + 1] as usize);
            if !jumped {
                return_pos = *pos + 2;
                jumped = true;
            }
            *pos = offset;
            hops += 1;
            if hops > 16 {
                return None; // loop guard
            }
            continue;
        }

        // End of name
        if byte == 0 {
            if !jumped {
                *pos += 1;
            } else {
                *pos = return_pos;
            }
            break;
        }

        // Label
        let len = byte as usize;
        *pos += 1;
        if *pos + len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[*pos..*pos + len]).ok()?;
        labels.push(label.to_string());
        *pos += len;
    }

    Some(labels.join("."))
}

#[inline]
fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    if *pos + 2 > data.len() {
        return None;
    }
    let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Some(v)
}

#[inline]
fn read_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > data.len() {
        return None;
    }
    let v = u32::from_be_bytes([
        data[*pos],
        data[*pos + 1],
        data[*pos + 2],
        data[*pos + 3],
    ]);
    *pos += 4;
    Some(v)
}

// Parsed record types we care about.
enum MdnsRecord {
    A {
        name: String,
        addr: Ipv4Addr,
    },
    Aaaa {
        name: String,
        addr: std::net::Ipv6Addr,
    },
    Ptr {
        name: String,
        target: String,
    },
    Srv {
        name: String,
        target: String,
        port: u16,
    },
    Other,
}

fn parse_record(data: &[u8], pos: &mut usize) -> Option<MdnsRecord> {
    let name = read_name(data, pos)?;
    let rtype = read_u16(data, pos)?;
    let _rclass = read_u16(data, pos)?; // may have cache-flush bit 0x8000
    let _ttl = read_u32(data, pos)?;
    let rdlen = read_u16(data, pos)? as usize;

    if *pos + rdlen > data.len() {
        return None;
    }
    let rdata_start = *pos;
    let rdata_end = *pos + rdlen;

    let rec = match rtype {
        1 => {
            // A record
            if rdlen != 4 {
                *pos = rdata_end;
                return Some(MdnsRecord::Other);
            }
            let addr = Ipv4Addr::new(
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            );
            MdnsRecord::A { name, addr }
        }
        28 => {
            // AAAA record
            if rdlen != 16 {
                *pos = rdata_end;
                return Some(MdnsRecord::Other);
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[*pos..*pos + 16]);
            MdnsRecord::Aaaa {
                name,
                addr: std::net::Ipv6Addr::from(bytes),
            }
        }
        12 => {
            // PTR record
            let mut p = rdata_start;
            let target = read_name(data, &mut p).unwrap_or_default();
            MdnsRecord::Ptr { name, target }
        }
        33 => {
            // SRV record: priority(2) weight(2) port(2) target(name)
            if rdlen < 6 {
                *pos = rdata_end;
                return Some(MdnsRecord::Other);
            }
            let mut p = rdata_start;
            let _priority = read_u16(data, &mut p)?;
            let _weight = read_u16(data, &mut p)?;
            let port = read_u16(data, &mut p)?;
            let target = read_name(data, &mut p).unwrap_or_default();
            MdnsRecord::Srv { name, target, port }
        }
        _ => MdnsRecord::Other,
    };

    *pos = rdata_end;
    Some(rec)
}

fn parse_section(data: &[u8], pos: &mut usize, count: u16) -> Vec<MdnsRecord> {
    let mut out = Vec::new();
    for _ in 0..count {
        match parse_record(data, pos) {
            Some(r) => out.push(r),
            None => break,
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Passive listener
// ---------------------------------------------------------------------------

/// Passive mDNS listener — bind once, loop forever receiving packets.
pub struct MdnsListener {
    pub registry: Arc<MdnsRegistry>,
}

impl MdnsListener {
    pub fn new(registry: Arc<MdnsRegistry>) -> Self {
        MdnsListener { registry }
    }

    /// Bind the multicast socket using SO_REUSEADDR/SO_REUSEPORT so we can
    /// co-exist with system mDNS daemons (Avahi, mDNSResponder).
    fn bind_socket() -> std::io::Result<std::net::UdpSocket> {
        use std::net::SocketAddrV4;

        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_reuse_address(true)?;
        #[cfg(not(windows))]
        socket.set_reuse_port(true)?;
        socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            MDNS_PORT,
        )))?;

        let udp: std::net::UdpSocket = socket.into();
        udp.join_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED)?;
        udp.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        Ok(udp)
    }

    /// Run the listener loop (blocks forever; call from a dedicated thread).
    pub fn run(&self) {
        let socket = match Self::bind_socket() {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[mDNS] cannot bind {}:{}: {} — device discovery disabled", MDNS_ADDR, MDNS_PORT, e);
                return;
            }
        };
        log::info!("[mDNS] passive listener active on {}:{}", MDNS_ADDR, MDNS_PORT);

        let mut buf = vec![0u8; 9000];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, _src)) => self.process(&buf[..len]),
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    log::debug!("[mDNS] recv_from: {}", e);
                }
            }
        }
    }

    fn process(&self, data: &[u8]) {
        if data.len() < 12 {
            return;
        }
        // DNS header fields
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let nscount = u16::from_be_bytes([data[8], data[9]]);
        let arcount = u16::from_be_bytes([data[10], data[11]]);

        let mut pos = 12usize;

        // Skip questions
        for _ in 0..qdcount {
            if read_name(data, &mut pos).is_none() {
                return;
            }
            pos += 4; // QTYPE + QCLASS
            if pos > data.len() {
                return;
            }
        }

        // Parse all resource record sections
        let mut records = parse_section(data, &mut pos, ancount);
        records.extend(parse_section(data, &mut pos, nscount));
        records.extend(parse_section(data, &mut pos, arcount));

        // --- first pass: collect host→IP and service associations ----------
        let mut host_ips: HashMap<String, String> = HashMap::new();
        let mut service_for_device: HashMap<String, String> = HashMap::new();

        for rec in &records {
            match rec {
                MdnsRecord::A { name, addr } => {
                    if let Some(bare) = strip_local(name) {
                        host_ips.insert(bare, addr.to_string());
                    }
                }
                MdnsRecord::Aaaa { name, addr } => {
                    if let Some(bare) = strip_local(name) {
                        host_ips.insert(bare, addr.to_string());
                    }
                }
                MdnsRecord::Ptr { name, target } => {
                    // name   = "_http._tcp.local"
                    // target = "MyDevice._http._tcp.local"
                    let svc_type = name
                        .trim_end_matches('.')
                        .trim_end_matches(".local")
                        .to_string();
                    // Derive device label from the first part of the instance name
                    if let Some(device) = instance_hostname(target) {
                        service_for_device.insert(device, svc_type);
                    }
                }
                MdnsRecord::Srv { name, target, .. } => {
                    // name   = "MyDevice._http._tcp.local"
                    // target = "mydevice.local"
                    if let Some(device) = strip_local(target) {
                        if let Some(svc) = extract_service_type(name) {
                            service_for_device.insert(device, svc);
                        }
                    }
                }
                MdnsRecord::Other => {}
            }
        }

        // --- second pass: update registry -----------------------------------
        for (host, ip) in &host_ips {
            self.registry.upsert(host, Some(ip.clone()), None);
        }
        for (device, svc) in &service_for_device {
            self.registry.upsert(device, None, Some(svc.clone()));
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip `.local` suffix (and any trailing dot) from a DNS name.
/// Returns `None` if the name isn't a `.local` name.
fn strip_local(name: &str) -> Option<String> {
    let n = name.trim_end_matches('.');
    n.strip_suffix(".local").map(|s| s.to_string())
}

/// Extract the device label from an mDNS service-instance name like
/// `"MyDevice._http._tcp.local"` → `"MyDevice"`.
fn instance_hostname(instance: &str) -> Option<String> {
    let n = instance.trim_end_matches('.').trim_end_matches(".local");
    // everything before the first `._`
    n.split("._").next().filter(|s| !s.is_empty()).map(|s| s.to_string())
}

/// Extract the `_service._proto` part from an mDNS instance name like
/// `"MyDevice._http._tcp.local"` → `"_http._tcp"`.
fn extract_service_type(name: &str) -> Option<String> {
    let n = name.trim_end_matches('.').trim_end_matches(".local");
    // Find the first `._` token
    if let Some(idx) = n.find("._") {
        let svc = &n[idx + 1..]; // skip the `.`
        if !svc.is_empty() {
            return Some(svc.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Public API — start listener / get devices
// ---------------------------------------------------------------------------

/// Spawn the passive mDNS listener thread and return a handle to the registry.
pub fn start_mdns_listener(registry: Arc<MdnsRegistry>) {
    let listener = MdnsListener::new(registry);
    std::thread::Builder::new()
        .name("mdns-listener".to_string())
        .spawn(move || listener.run())
        .expect("failed to spawn mDNS listener thread");
}

/// Convenience: create a fresh registry, start the listener, and return the registry.
pub fn start() -> Arc<MdnsRegistry> {
    let registry = Arc::new(MdnsRegistry::new());
    start_mdns_listener(registry.clone());
    registry
}

/// Return all devices currently in the registry.
pub fn get_devices(registry: &Arc<MdnsRegistry>) -> Vec<MdnsDevice> {
    registry.all_devices()
}

// ---------------------------------------------------------------------------
// mDNS Responder
// ---------------------------------------------------------------------------

/// A configured local hostname that the responder will answer for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsLocalRecord {
    /// Bare hostname (without `.local`).
    pub hostname: String,
    /// IPv4 address to respond with.
    pub ip: Ipv4Addr,
    /// TTL in seconds.
    pub ttl: u32,
}

/// mDNS responder — answers queries for configured `.local` hostnames.
pub struct MdnsResponder {
    /// Static records to serve.
    pub records: Vec<MdnsLocalRecord>,
}

impl MdnsResponder {
    pub fn new(records: Vec<MdnsLocalRecord>) -> Self {
        MdnsResponder { records }
    }

    /// Run the responder loop (blocks forever; call from a dedicated thread).
    /// Shares the same multicast socket logic as the listener.
    pub fn run(&self) {
        // Bind a separate socket for sending responses (unicast or multicast).
        let send_socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[mDNS responder] cannot bind send socket: {}", e);
                return;
            }
        };

        // Receive socket (same as listener)
        let recv_socket = match MdnsListener::bind_socket() {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[mDNS responder] cannot bind recv socket: {}", e);
                return;
            }
        };

        log::info!("[mDNS responder] active, serving {} record(s)", self.records.len());

        let mdns_addr: std::net::SocketAddr = format!("{}:{}", MDNS_ADDR, MDNS_PORT).parse().unwrap();
        let mut buf = vec![0u8; 9000];

        loop {
            match recv_socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    if let Some(response) = self.maybe_respond(&buf[..len]) {
                        // Send response to the querier (unicast) or multicast
                        let dest = if src.port() == MDNS_PORT { mdns_addr } else { src };
                        if let Err(e) = send_socket.send_to(&response, dest) {
                            log::debug!("[mDNS responder] send error: {}", e);
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    log::debug!("[mDNS responder] recv_from: {}", e);
                }
            }
        }
    }

    /// If the packet is an mDNS query for one of our hostnames, build and return a response.
    pub fn maybe_respond(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 12 {
            return None;
        }

        // Check QR bit (bit 15 of flags) — must be 0 (query)
        let flags = u16::from_be_bytes([data[2], data[3]]);
        if flags & 0x8000 != 0 {
            return None; // It's a response, not a query
        }

        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let mut pos = 12usize;
        let mut matched: Vec<&MdnsLocalRecord> = Vec::new();

        for _ in 0..qdcount {
            let name = read_name(data, &mut pos)?;
            let qtype = read_u16(data, &mut pos)?;
            let _qclass = read_u16(data, &mut pos)?;

            // We only handle A queries (type 1) for .local hostnames
            if qtype != 1 && qtype != 255 /* ANY */ {
                continue;
            }

            if let Some(bare) = strip_local(&name) {
                if let Some(rec) = self.records.iter().find(|r| r.hostname.eq_ignore_ascii_case(&bare)) {
                    matched.push(rec);
                }
            }
        }

        if matched.is_empty() {
            return None;
        }

        // Build DNS response
        let mut response = Vec::with_capacity(256);

        // Transaction ID (copy from query)
        response.push(data[0]);
        response.push(data[1]);

        // Flags: QR=1, AA=1, RCODE=0
        response.push(0x84);
        response.push(0x00);

        // QDCOUNT = 0 (mDNS responses omit the question)
        response.extend_from_slice(&0u16.to_be_bytes());
        // ANCOUNT
        response.extend_from_slice(&(matched.len() as u16).to_be_bytes());
        // NSCOUNT
        response.extend_from_slice(&0u16.to_be_bytes());
        // ARCOUNT
        response.extend_from_slice(&0u16.to_be_bytes());

        for rec in matched {
            // Encode name: hostname.local
            for label in rec.hostname.split('.') {
                response.push(label.len() as u8);
                response.extend_from_slice(label.as_bytes());
            }
            response.push(5); // "local"
            response.extend_from_slice(b"local");
            response.push(0); // end of name

            // TYPE A (1), CLASS IN (1, with cache-flush bit 0x8000)
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0x8001u16.to_be_bytes());

            // TTL
            response.extend_from_slice(&rec.ttl.to_be_bytes());

            // RDLENGTH = 4
            response.extend_from_slice(&4u16.to_be_bytes());

            // RDATA = IPv4
            let octets = rec.ip.octets();
            response.extend_from_slice(&octets);
        }

        Some(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_local() {
        assert_eq!(strip_local("mydevice.local"), Some("mydevice".to_string()));
        assert_eq!(strip_local("mydevice.local."), Some("mydevice".to_string()));
        assert_eq!(strip_local("example.com"), None);
    }

    #[test]
    fn test_instance_hostname() {
        assert_eq!(
            instance_hostname("MyDevice._http._tcp.local"),
            Some("MyDevice".to_string())
        );
    }

    #[test]
    fn test_extract_service_type() {
        assert_eq!(
            extract_service_type("MyDevice._http._tcp.local"),
            Some("_http._tcp".to_string())
        );
    }

    #[test]
    fn test_registry_upsert_and_lookup() {
        let reg = MdnsRegistry::new();
        reg.upsert("laptop", Some("192.168.1.5".to_string()), Some("_ssh._tcp".to_string()));
        assert_eq!(reg.lookup_ip("laptop"), Some("192.168.1.5".to_string()));
        let devs = reg.all_devices();
        assert_eq!(devs.len(), 1);
        assert!(devs[0].services.contains(&"_ssh._tcp".to_string()));
    }

    /// Build a minimal mDNS query for `hostname.local` (type A).
    fn build_mdns_query(hostname: &str) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0u16.to_be_bytes()); // TX id = 0 for mDNS
        pkt.extend_from_slice(&0u16.to_be_bytes()); // flags = query
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // QNAME
        for label in hostname.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(5); // "local"
        pkt.extend_from_slice(b"local");
        pkt.push(0); // end
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        pkt
    }

    #[test]
    fn test_responder_matches_configured_host() {
        let records = vec![MdnsLocalRecord {
            hostname: "myserver".to_string(),
            ip: Ipv4Addr::new(192, 168, 1, 42),
            ttl: 120,
        }];
        let responder = MdnsResponder::new(records);

        let query = build_mdns_query("myserver");
        let response = responder.maybe_respond(&query);
        assert!(response.is_some(), "Expected a response for myserver.local");

        let resp = response.unwrap();
        // QR bit should be set
        assert!(resp[2] & 0x80 != 0);
        // Should contain the IP 192.168.1.42 somewhere
        assert!(resp.windows(4).any(|w| w == [192, 168, 1, 42]));
    }

    #[test]
    fn test_responder_ignores_unknown_host() {
        let records = vec![MdnsLocalRecord {
            hostname: "myserver".to_string(),
            ip: Ipv4Addr::new(192, 168, 1, 42),
            ttl: 120,
        }];
        let responder = MdnsResponder::new(records);

        let query = build_mdns_query("unknownhost");
        let response = responder.maybe_respond(&query);
        assert!(response.is_none(), "Should not respond for unknown hosts");
    }

    #[test]
    fn test_responder_ignores_mdns_responses() {
        let records = vec![MdnsLocalRecord {
            hostname: "myserver".to_string(),
            ip: Ipv4Addr::new(192, 168, 1, 42),
            ttl: 120,
        }];
        let responder = MdnsResponder::new(records);

        // Build a "response" (QR=1) packet
        let mut pkt = build_mdns_query("myserver");
        pkt[2] |= 0x80; // set QR bit
        let response = responder.maybe_respond(&pkt);
        assert!(response.is_none(), "Should ignore mDNS response packets");
    }
}
