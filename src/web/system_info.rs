//! System Information Module
//!
//! Cross-platform system monitoring providing real hardware metrics including:
//! - CPU usage and temperature
//! - Memory usage (RAM)
//! - Disk space usage
//! - Network statistics
//! - System uptime
//! - Load average (Unix systems)
//!
//! Compatible with Windows, Linux, and macOS

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::{
    System, SystemExt, CpuExt, DiskExt, NetworkExt, ComponentExt, 
    ProcessExt, RefreshKind, NetworksExt, PidExt, CpuRefreshKind, ProcessRefreshKind
};

/// Complete system information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disk: DiskInfo,
    pub network: NetworkInfo,
    pub thermal: ThermalInfo,
    pub system: SystemDetails,
    pub processes: ProcessInfo,
}

/// CPU information and usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub usage_percent: f32,
    pub cores_logical: usize,
    pub cores_physical: usize,
    pub frequency_mhz: u64,
    pub brand: String,
    pub vendor: String,
    pub per_core_usage: Vec<f32>,
}

/// Memory usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f32,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_usage_percent: f32,
}

/// Disk space information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub disks: Vec<DiskDetails>,
    pub total_space_bytes: u64,
    pub used_space_bytes: u64,
    pub available_space_bytes: u64,
    pub usage_percent: f32,
}

/// Individual disk information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskDetails {
    pub name: String,
    pub mount_point: String,
    pub file_system: String,
    pub total_space_bytes: u64,
    pub available_space_bytes: u64,
    pub usage_percent: f32,
    pub disk_type: String,
    pub is_removable: bool,
}

/// Network interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interfaces: Vec<NetworkInterface>,
    pub total_bytes_received: u64,
    pub total_bytes_transmitted: u64,
    pub total_packets_received: u64,
    pub total_packets_transmitted: u64,
}

/// Individual network interface details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub bytes_received: u64,
    pub bytes_transmitted: u64,
    pub packets_received: u64,
    pub packets_transmitted: u64,
    pub errors_received: u64,
    pub errors_transmitted: u64,
}

/// Temperature and thermal information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThermalInfo {
    pub cpu_temperature_celsius: Option<f32>,
    pub gpu_temperature_celsius: Option<f32>,
    pub components: Vec<ThermalComponent>,
    pub thermal_state: ThermalState,
}

/// Individual thermal component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThermalComponent {
    pub label: String,
    pub temperature_celsius: f32,
    pub max_temperature_celsius: Option<f32>,
    pub critical_temperature_celsius: Option<f32>,
}

/// Overall thermal state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThermalState {
    Normal,
    Warm,
    Hot,
    Critical,
    Unknown,
}

/// System details and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemDetails {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub uptime_seconds: u64,
    pub boot_time_unix: u64,
    pub load_average: LoadAverage,
}

/// System load average (Unix systems)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAverage {
    pub one_minute: f64,
    pub five_minutes: f64,
    pub fifteen_minutes: f64,
}

/// Process information summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub total_processes: usize,
    pub running_processes: usize,
    pub atlas_process: Option<ProcessDetails>,
}

/// Atlas DNS process details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetails {
    pub pid: u32,
    pub name: String,
    pub cpu_usage_percent: f32,
    pub memory_bytes: u64,
    pub memory_percent: f32,
    pub start_time_unix: u64,
    pub runtime_seconds: u64,
}

/// System Information Collector
pub struct SystemInfoCollector {
    system: System,
    last_update: SystemTime,
    update_interval: Duration,
}

impl SystemInfoCollector {
    /// Create a new system information collector
    pub fn new() -> Self {
        let refresh_kind = RefreshKind::new()
            .with_cpu(CpuRefreshKind::new().with_frequency().with_cpu_usage())
            .with_memory()
            .with_networks()
            .with_disks()
            .with_components()
            .with_processes(ProcessRefreshKind::new().with_cpu());

        let mut system = System::new_with_specifics(refresh_kind);
        system.refresh_all();

        Self {
            system,
            last_update: SystemTime::now(),
            update_interval: Duration::from_secs(2), // Update every 2 seconds
        }
    }

    /// Update system information if enough time has passed
    pub fn refresh_if_needed(&mut self) {
        if self.last_update.elapsed().unwrap_or(Duration::MAX) >= self.update_interval {
            self.system.refresh_all();
            self.last_update = SystemTime::now();
        }
    }

    /// Get complete system information
    pub fn get_system_info(&mut self) -> SystemInfo {
        self.refresh_if_needed();

        SystemInfo {
            cpu: self.get_cpu_info(),
            memory: self.get_memory_info(),
            disk: self.get_disk_info(),
            network: self.get_network_info(),
            thermal: self.get_thermal_info(),
            system: self.get_system_details(),
            processes: self.get_process_info(),
        }
    }

    /// Get CPU information
    fn get_cpu_info(&self) -> CpuInfo {
        let cpus = self.system.cpus();
        let global_cpu = self.system.global_cpu_info();
        
        let usage_percent = global_cpu.cpu_usage();
        let per_core_usage: Vec<f32> = cpus.iter().map(|cpu| cpu.cpu_usage()).collect();
        
        let cores_logical = cpus.len();
        let cores_physical = self.system.physical_core_count().unwrap_or(cores_logical);
        
        // Get CPU brand and vendor from first CPU
        let (brand, vendor) = if let Some(cpu) = cpus.first() {
            (cpu.brand().to_string(), cpu.vendor_id().to_string())
        } else {
            ("Unknown".to_string(), "Unknown".to_string())
        };

        let frequency_mhz = cpus.first()
            .map(|cpu| cpu.frequency())
            .unwrap_or(0);

        CpuInfo {
            usage_percent,
            cores_logical,
            cores_physical,
            frequency_mhz,
            brand,
            vendor,
            per_core_usage,
        }
    }

    /// Get memory information
    fn get_memory_info(&self) -> MemoryInfo {
        let total_bytes = self.system.total_memory();
        let used_bytes = self.system.used_memory();
        let available_bytes = self.system.available_memory();
        let usage_percent = if total_bytes > 0 {
            (used_bytes as f32 / total_bytes as f32) * 100.0
        } else {
            0.0
        };

        let swap_total_bytes = self.system.total_swap();
        let swap_used_bytes = self.system.used_swap();
        let swap_usage_percent = if swap_total_bytes > 0 {
            (swap_used_bytes as f32 / swap_total_bytes as f32) * 100.0
        } else {
            0.0
        };

        MemoryInfo {
            total_bytes,
            used_bytes,
            available_bytes,
            usage_percent,
            swap_total_bytes,
            swap_used_bytes,
            swap_usage_percent,
        }
    }

    /// Get disk information
    fn get_disk_info(&self) -> DiskInfo {
        let disks: Vec<DiskDetails> = self.system.disks()
            .iter()
            .map(|disk| {
                let total_space_bytes = disk.total_space();
                let available_space_bytes = disk.available_space();
                let used_space_bytes = total_space_bytes - available_space_bytes;
                let usage_percent = if total_space_bytes > 0 {
                    (used_space_bytes as f32 / total_space_bytes as f32) * 100.0
                } else {
                    0.0
                };

                DiskDetails {
                    name: disk.name().to_string_lossy().to_string(),
                    mount_point: disk.mount_point().to_string_lossy().to_string(),
                    file_system: String::from_utf8_lossy(disk.file_system()).to_string(),
                    total_space_bytes,
                    available_space_bytes,
                    usage_percent,
                    disk_type: "Unknown".to_string(), // disk.type_() is not available in this version
                    is_removable: false, // disk.is_removable() is not available in this version
                }
            })
            .collect();

        // Calculate totals
        let total_space_bytes = disks.iter().map(|d| d.total_space_bytes).sum();
        let available_space_bytes = disks.iter().map(|d| d.available_space_bytes).sum();
        let used_space_bytes = total_space_bytes - available_space_bytes;
        let usage_percent = if total_space_bytes > 0 {
            (used_space_bytes as f32 / total_space_bytes as f32) * 100.0
        } else {
            0.0
        };

        DiskInfo {
            disks,
            total_space_bytes,
            used_space_bytes,
            available_space_bytes,
            usage_percent,
        }
    }

    /// Get network information
    fn get_network_info(&self) -> NetworkInfo {
        let interfaces: Vec<NetworkInterface> = self.system.networks()
            .iter()
            .map(|(name, network)| {
                NetworkInterface {
                    name: name.clone(),
                    bytes_received: network.received(),
                    bytes_transmitted: network.transmitted(),
                    packets_received: network.packets_received(),
                    packets_transmitted: network.packets_transmitted(),
                    errors_received: network.errors_on_received(),
                    errors_transmitted: network.errors_on_transmitted(),
                }
            })
            .collect();

        let total_bytes_received = interfaces.iter().map(|i| i.bytes_received).sum();
        let total_bytes_transmitted = interfaces.iter().map(|i| i.bytes_transmitted).sum();
        let total_packets_received = interfaces.iter().map(|i| i.packets_received).sum();
        let total_packets_transmitted = interfaces.iter().map(|i| i.packets_transmitted).sum();

        NetworkInfo {
            interfaces,
            total_bytes_received,
            total_bytes_transmitted,
            total_packets_received,
            total_packets_transmitted,
        }
    }

    /// Get thermal information
    fn get_thermal_info(&self) -> ThermalInfo {
        let components: Vec<ThermalComponent> = self.system.components()
            .iter()
            .map(|component| {
                ThermalComponent {
                    label: component.label().to_string(),
                    temperature_celsius: component.temperature(),
                    max_temperature_celsius: Some(component.max()),
                    critical_temperature_celsius: component.critical(),
                }
            })
            .collect();

        // Find CPU and GPU temperatures
        let cpu_temperature_celsius = components
            .iter()
            .find(|c| c.label.to_lowercase().contains("cpu") || c.label.to_lowercase().contains("core"))
            .map(|c| c.temperature_celsius);

        let gpu_temperature_celsius = components
            .iter()
            .find(|c| c.label.to_lowercase().contains("gpu") || c.label.to_lowercase().contains("graphics"))
            .map(|c| c.temperature_celsius);

        // Determine thermal state
        let max_temp = components.iter()
            .map(|c| c.temperature_celsius)
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(0.0);

        let thermal_state = match max_temp {
            t if t < 50.0 => ThermalState::Normal,
            t if t < 70.0 => ThermalState::Warm,
            t if t < 85.0 => ThermalState::Hot,
            t if t >= 85.0 => ThermalState::Critical,
            _ => ThermalState::Unknown,
        };

        ThermalInfo {
            cpu_temperature_celsius,
            gpu_temperature_celsius,
            components,
            thermal_state,
        }
    }

    /// Get system details
    fn get_system_details(&self) -> SystemDetails {
        let hostname = self.system.host_name().unwrap_or_else(|| "Unknown".to_string());
        let os_name = self.system.name().unwrap_or_else(|| "Unknown".to_string());
        let os_version = self.system.os_version().unwrap_or_else(|| "Unknown".to_string());
        let kernel_version = self.system.kernel_version().unwrap_or_else(|| "Unknown".to_string());
        let architecture = std::env::consts::ARCH.to_string(); // Use built-in architecture
        
        let uptime_seconds = self.system.uptime();
        let boot_time_unix = self.system.boot_time();

        // Load average (available on Unix systems)
        let load_average = LoadAverage {
            one_minute: self.system.load_average().one,
            five_minutes: self.system.load_average().five,
            fifteen_minutes: self.system.load_average().fifteen,
        };

        SystemDetails {
            hostname,
            os_name,
            os_version,
            kernel_version,
            architecture,
            uptime_seconds,
            boot_time_unix,
            load_average,
        }
    }

    /// Get process information
    fn get_process_info(&self) -> ProcessInfo {
        let processes = self.system.processes();
        let total_processes = processes.len();
        
        let running_processes = processes
            .values()
            .filter(|p| p.status() == sysinfo::ProcessStatus::Run)
            .count();

        // Find Atlas DNS process
        let atlas_process = processes
            .values()
            .find(|p| {
                p.name().to_lowercase().contains("atlas")
            })
            .map(|process| {
                let start_time_unix = process.start_time();
                let runtime_seconds = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_sub(start_time_unix);

                ProcessDetails {
                    pid: process.pid().as_u32(),
                    name: process.name().to_string(),
                    cpu_usage_percent: process.cpu_usage(),
                    memory_bytes: process.memory(),
                    memory_percent: (process.memory() as f32 / self.system.total_memory() as f32) * 100.0,
                    start_time_unix,
                    runtime_seconds,
                }
            });

        ProcessInfo {
            total_processes,
            running_processes,
            atlas_process,
        }
    }
}

impl Default for SystemInfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for formatting system information
pub mod format {
    /// Format bytes as human-readable string
    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
        
        if bytes == 0 {
            return "0 B".to_string();
        }
        
        let size = bytes as f64;
        let unit_index = (size.log10() / 3.0).floor() as usize;
        let unit_index = unit_index.min(UNITS.len() - 1);
        
        let value = size / 1000_f64.powi(unit_index as i32);
        
        if value < 10.0 && unit_index > 0 {
            format!("{:.1} {}", value, UNITS[unit_index])
        } else {
            format!("{:.0} {}", value, UNITS[unit_index])
        }
    }
    
    /// Format duration as human-readable string
    pub fn format_duration(seconds: u64) -> String {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;
        
        if days > 0 {
            format!("{}d {}h {}m", days, hours, minutes)
        } else if hours > 0 {
            format!("{}h {}m", hours, minutes)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, secs)
        } else {
            format!("{}s", secs)
        }
    }
    
    /// Format temperature with color coding
    pub fn format_temperature(celsius: f32) -> (String, &'static str) {
        let temp_str = format!("{:.1}°C", celsius);
        let color_class = match celsius {
            t if t < 50.0 => "text-success",
            t if t < 70.0 => "text-warning",
            t if t < 85.0 => "text-danger",
            _ => "text-danger fw-bold",
        };
        (temp_str, color_class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_info_collector_creation() {
        let collector = SystemInfoCollector::new();
        assert!(collector.update_interval > Duration::ZERO);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format::format_bytes(0), "0 B");
        assert_eq!(format::format_bytes(1000), "1.0 KB");
        assert_eq!(format::format_bytes(1000000), "1.0 MB");
        assert_eq!(format::format_bytes(1000000000), "1.0 GB");
        assert_eq!(format::format_bytes(1500), "1.5 KB");
        assert_eq!(format::format_bytes(10000), "10 KB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format::format_duration(30), "30s");
        assert_eq!(format::format_duration(90), "1m 30s");
        assert_eq!(format::format_duration(3661), "1h 1m");
        assert_eq!(format::format_duration(90061), "1d 1h 1m");
    }

    #[test]
    fn test_format_temperature() {
        let (temp_str, color) = format::format_temperature(45.5);
        assert_eq!(temp_str, "45.5°C");
        assert_eq!(color, "text-success");
        
        let (temp_str, color) = format::format_temperature(75.0);
        assert_eq!(temp_str, "75.0°C");
        assert_eq!(color, "text-danger");
    }
}