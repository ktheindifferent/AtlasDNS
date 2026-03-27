//! mDNS responder and service browser using the `mdns-sd` crate.
//!
//! Responds to `.local` queries via multicast DNS (RFC 6762) and exposes
//! discovered devices through a REST endpoint at `GET /api/mdns/devices`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Device registry
// ---------------------------------------------------------------------------

/// A device discovered or registered via mDNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsDevice {
    pub hostname: String,
    pub ip: Option<String>,
    pub services: Vec<String>,
    pub port: Option<u16>,
    pub last_seen: u64,
}

/// Thread-safe registry of mDNS devices.
pub struct MdnsResponder {
    devices: RwLock<HashMap<String, MdnsDevice>>,
    daemon: ServiceDaemon,
}

impl MdnsResponder {
    /// Create a new mDNS responder backed by `mdns-sd`.
    pub fn new() -> Result<Self, String> {
        let daemon =
            ServiceDaemon::new().map_err(|e| format!("Failed to start mDNS daemon: {}", e))?;
        Ok(Self {
            devices: RwLock::new(HashMap::new()),
            daemon,
        })
    }

    /// Register this host as a `.local` service so it responds to mDNS queries.
    pub fn register_service(
        &self,
        instance_name: &str,
        service_type: &str,
        port: u16,
        properties: &[(&str, &str)],
    ) -> Result<(), String> {
        let host = format!("{}.local.", instance_name);
        let props: HashMap<String, String> = properties
            .iter()
            .map(|&(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let info = ServiceInfo::new(
            service_type,
            instance_name,
            &host,
            "",   // auto-detect IP
            port,
            Some(props),
        )
        .map_err(|e| format!("Failed to build ServiceInfo: {}", e))?;

        self.daemon
            .register(info)
            .map_err(|e| format!("Failed to register mDNS service: {}", e))?;

        log::info!(
            "[mDNS] Registered service {}.{} on port {}",
            instance_name,
            service_type,
            port
        );
        Ok(())
    }

    /// Start browsing for a service type (e.g. `_http._tcp.local.`).
    /// Discovered devices are added to the internal registry.
    pub fn browse(&self, service_type: &str) -> Result<(), String> {
        let receiver = self
            .daemon
            .browse(service_type)
            .map_err(|e| format!("Failed to browse: {}", e))?;

        let devices = Arc::new(RwLock::new(Vec::<(String, MdnsDevice)>::new()));
        let devices_clone = devices.clone();

        let svc_type = service_type.to_string();
        std::thread::Builder::new()
            .name(format!("mdns-browse-{}", service_type))
            .spawn(move || {
                while let Ok(event) = receiver.recv() {
                    match event {
                        ServiceEvent::ServiceResolved(info) => {
                            let hostname = info
                                .get_fullname()
                                .trim_end_matches('.')
                                .trim_end_matches(".local")
                                .split('.')
                                .next()
                                .unwrap_or("")
                                .to_string();

                            let ip = info
                                .get_addresses()
                                .iter()
                                .next()
                                .map(|a| a.to_string());

                            let device = MdnsDevice {
                                hostname: hostname.clone(),
                                ip,
                                services: vec![svc_type.clone()],
                                port: Some(info.get_port()),
                                last_seen: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            };

                            if let Ok(mut guard) = devices_clone.write() {
                                guard.push((hostname, device));
                            }
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            log::debug!("[mDNS] Service removed: {}", fullname);
                        }
                        _ => {}
                    }
                }
            })
            .map_err(|e| format!("Failed to spawn browse thread: {}", e))?;

        // Periodically flush discovered devices into the main registry
        let self_devices = &self.devices;
        if let Ok(guard) = devices.read() {
            for (hostname, device) in guard.iter() {
                if let Ok(mut registry) = self_devices.write() {
                    registry.insert(hostname.clone(), device.clone());
                }
            }
        }

        Ok(())
    }

    /// Upsert a device into the registry (used by the passive listener).
    pub fn upsert(&self, hostname: &str, ip: Option<String>, service: Option<String>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut guard = self.devices.write().unwrap_or_else(|e| e.into_inner());
        let entry = guard
            .entry(hostname.to_string())
            .or_insert_with(|| MdnsDevice {
                hostname: hostname.to_string(),
                ip: None,
                services: Vec::new(),
                port: None,
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

    /// Return all known mDNS devices (for the REST endpoint).
    pub fn all_devices(&self) -> Vec<MdnsDevice> {
        self.devices
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Look up an IP for a `.local` hostname.
    pub fn lookup(&self, hostname: &str) -> Option<String> {
        self.devices
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(hostname)
            .and_then(|d| d.ip.clone())
    }

    /// Shut down the mDNS daemon gracefully.
    pub fn shutdown(&self) {
        if let Err(e) = self.daemon.shutdown() {
            log::warn!("[mDNS] Shutdown error: {}", e);
        }
    }
}

/// JSON response for `GET /api/mdns/devices`.
#[derive(Debug, Serialize, Deserialize)]
pub struct MdnsDevicesResponse {
    pub devices: Vec<MdnsDevice>,
    pub count: usize,
}

impl MdnsDevicesResponse {
    pub fn from_responder(responder: &MdnsResponder) -> Self {
        let devices = responder.all_devices();
        let count = devices.len();
        Self { devices, count }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdns_device_serde() {
        let device = MdnsDevice {
            hostname: "myhost".into(),
            ip: Some("192.168.1.1".into()),
            services: vec!["_http._tcp".into()],
            port: Some(80),
            last_seen: 1234567890,
        };
        let json = serde_json::to_string(&device).unwrap();
        let parsed: MdnsDevice = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hostname, "myhost");
        assert_eq!(parsed.port, Some(80));
    }

    #[test]
    fn test_mdns_devices_response() {
        let resp = MdnsDevicesResponse {
            devices: vec![],
            count: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"count\":0"));
    }
}
