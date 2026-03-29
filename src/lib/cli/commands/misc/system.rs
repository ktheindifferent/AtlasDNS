//! System information command
//!
//! Provides detailed system information including kernel, OS, and hardware details.

use clap::Args;

#[derive(Args)]
pub struct SystemArgs {
    /// Show all system information
    #[arg(short = 'a', long)]
    show_all: bool,
    
    /// Show kernel name
    #[arg(short = 's', long)]
    show_kernel: bool,
    
    /// Show network node hostname
    #[arg(short = 'n', long)]
    show_nodename: bool,
    
    /// Show kernel release
    #[arg(short = 'r', long)]
    show_release: bool,
    
    /// Show kernel version
    #[arg(short = 'v', long)]
    show_version: bool,
    
    /// Show machine hardware name
    #[arg(short = 'm', long)]
    show_machine: bool,
    
    /// Show operating system
    #[arg(short = 'o', long)]
    show_os: bool,
}

/// Determines if no specific flags were provided (all are false)
fn should_show_all_info(args: &SystemArgs) -> bool {
    !args.show_all && !args.show_kernel && !args.show_nodename && 
    !args.show_release && !args.show_version && !args.show_machine && 
    !args.show_os
}

pub fn handle_system_command(args: SystemArgs) {
    if should_show_all_info(&args) {
        // Default behavior when no flags are specified
        show_all_system_info();
    } else {
        // Show specific information based on flags
        if args.show_all || args.show_kernel {
            show_kernel_info();
        }
        if args.show_all || args.show_nodename {
            show_nodename_info();
        }
        if args.show_all || args.show_release {
            show_release_info();
        }
        if args.show_all || args.show_version {
            show_version_info();
        }
        if args.show_all || args.show_machine {
            show_machine_info();
        }
        if args.show_all || args.show_os {
            show_os_info();
        }
    }
}

fn show_all_system_info() {
    println!("Showing all system information...");
    show_kernel_info();
    show_nodename_info();
    show_release_info();
    show_version_info();
    show_machine_info();
    show_os_info();
}

fn show_kernel_info() {
    println!("Kernel: Linux");
}

fn show_nodename_info() {
    println!("Nodename: my-host");
}

fn show_release_info() {
    println!("Release: 5.4.0-42-generic");
}

fn show_version_info() {
    println!("Version: #46-Ubuntu SMP Fri Jul 10 00:24:00 UTC 2020");
}

fn show_machine_info() {
    println!("Machine: x86_64");
}

fn show_os_info() {
    println!("OS: GNU/Linux");
}