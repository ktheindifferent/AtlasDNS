// src/mdns.rs

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use serde::{Serialize, Deserialize};

/// mDNS Device Information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MdnsDevice {
    pub name: String,
    pub address: IpAddr,
    pub port: u16,
    pub service_type: String,
}

/// mDNS Responder
pub struct MdnsResponder {
    devices: Arc<Mutex<HashMap<String, MdnsDevice>>>, // Maps device names to their info
}

impl Default for MdnsResponder {
    fn default() -> Self {
        Self::new()
    }
}

impl MdnsResponder {
    /// Create a new mDNS responder
    pub fn new() -> Self {
        MdnsResponder {
            devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a new mDNS device
    pub fn register_device(&self, device: MdnsDevice) {
        let mut devices = self.devices.lock().unwrap();
        devices.insert(device.name.clone(), device);
    }
}

