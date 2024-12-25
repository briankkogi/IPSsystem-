mod ui;

use std::thread;
use pnet::datalink;
use pnet::packet::{tcp, Packet};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use log::{info, error};
use simplelog::{Config, SimpleLogger, LevelFilter};
use std::collections::{HashSet, HashMap};
use std::net::Ipv4Addr;
use std::time::{Instant, Duration};
use chrono::Utc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use once_cell::sync::Lazy;
use std::sync::mpsc::{self, Sender};

#[derive(Clone)]
pub struct CapturedPacket {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
    pub port: u16,
    pub flags: u16,
}

// Add these new types after the imports
type AlertCount = HashMap<Ipv4Addr, (u32, Instant)>;
const ALERT_THRESHOLD: u32 = 5;
const ALERT_COOLDOWN: Duration = Duration::from_secs(300); // 5 minutes

// Add these constants for better tuning
const MIN_PORTS_FOR_SCAN: usize = 50;  // Increased from 30
const SCAN_TIME_WINDOW: u64 = 60;      // Reduced from 180
const CONSECUTIVE_ALERTS: u32 = 1;      // Number of alerts before considering it a real threat

// Add these new constants
const ACK_SCAN_COOLDOWN: Duration = Duration::from_secs(5);  // Wait 5 seconds between ACK scan alerts
const MIN_PORT_DIFFERENCE: i32 = 5;  // Minimum port difference to consider it a new scan

struct ScanContext {
    first_seen: Instant,
    port_count: usize,
    consecutive_hits: u32,
    last_port: u16,
    last_ack_alert: Instant,
    last_scan_type: Option<String>,
}

static SCAN_CONTEXTS: Lazy<Mutex<HashMap<Ipv4Addr, ScanContext>>> = 
    Lazy::new(|| Mutex::new(HashMap::new()));

fn main() {
    // Create two channels: one for alerts, one for captured packets
    let (alert_tx, alert_rx) = mpsc::channel();
    let (packet_tx, packet_rx) = mpsc::channel();  // <-- new channel
    
    // List all available interfaces first
    let interfaces = datalink::interfaces();
    println!("Available interfaces:");
    for iface in &interfaces {
        println!("Interface: {} ({:?})", iface.name, iface.ips);
    }
    
    // Create UI instance first to get pause handle
    let ui = ui::IdsUI::new(alert_rx, packet_rx);  // Pass new receiver to UI
    let pause_handle = ui.get_pause_handle();

    // Spawn IDS monitoring thread
    thread::spawn(move || {
        run_ids_monitor(alert_tx, packet_tx, pause_handle);
    });
    
    // Run UI
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "IDS Monitor",
        native_options,
        Box::new(|_cc| Box::new(ui)),
    ).expect("Failed to start UI");
}

fn run_ids_monitor(alert_tx: Sender<ui::Alert>, packet_tx: std::sync::mpsc::Sender<CapturedPacket>, pause_handle: Arc<AtomicBool>) {
    SimpleLogger::init(LevelFilter::Info, Config::default()).unwrap();

    // Get network interfaces - try common VMware interface names
    let interface = get_network_interface("en0")
        .or_else(|| get_network_interface("eth0"))
        .or_else(|| get_network_interface("vmnet1"))
        .or_else(|| get_network_interface("vmnet8"))
        .expect("No suitable network interface found");

    info!("Using interface: {} with IPs: {:?}", interface.name, interface.ips);

    // Fetch the IP address of the device
    let device_ip = get_device_ip(&interface).expect("Failed to get device IP address");
    info!("Monitoring attacks targeting IP: {}", device_ip);

    // Create a channel for packet capture
    let mut rx = match create_channel(&interface).expect("Failed to create channel") {
        datalink::Channel::Ethernet(_, rx) => rx,
        _ => panic!("Unhandled channel type"),
    };

    info!("Listening for packets...");

    let mut seen_ports: HashMap<Ipv4Addr, HashSet<u16>> = HashMap::new();
    let mut alert_counts: AlertCount = HashMap::new();
    let whitelist = vec![
        device_ip, // Add the device's IP address to the whitelist
    ];

    let ip_ranges = vec![
        // Cloud Services
        Ipv4Addr::new(52, 0, 0, 0)..=Ipv4Addr::new(52, 255, 255, 255),    // Amazon AWS
        Ipv4Addr::new(17, 0, 0, 0)..=Ipv4Addr::new(17, 255, 255, 255),    // Apple
        Ipv4Addr::new(20, 0, 0, 0)..=Ipv4Addr::new(20, 255, 255, 255),    // Microsoft
        Ipv4Addr::new(104, 16, 0, 0)..=Ipv4Addr::new(104, 31, 255, 255),  // Cloudflare
        Ipv4Addr::new(172, 64, 0, 0)..=Ipv4Addr::new(172, 71, 255, 255),  // Cloudflare
        // Local Networks
        Ipv4Addr::new(192, 168, 0, 0)..=Ipv4Addr::new(192, 168, 255, 255),  // Private network
        Ipv4Addr::new(10, 0, 0, 0)..=Ipv4Addr::new(10, 255, 255, 255),      // Private network
        Ipv4Addr::new(172, 16, 0, 0)..=Ipv4Addr::new(172, 31, 255, 255),    // Private network
    ];

    // Listen and process packets
    loop {
        // Check if monitoring is paused
        if pause_handle.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));
            continue;
        }

        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            // Send minimal packet info to the Inspector tab
                            let captured = CapturedPacket {
                                timestamp: Utc::now(),
                                source_ip: ipv4_packet.get_source(),
                                dest_ip: ipv4_packet.get_destination(),
                                port: tcp_packet.get_destination(),
                                flags: tcp_packet.get_flags(),
                            };
                            let _ = packet_tx.send(captured);
                        }
                    }
                    process_packet(&ethernet, &mut seen_ports, &whitelist, &ip_ranges, &mut alert_counts, &alert_tx);
                } else {
                    error!("Failed to parse packet");
                }
            }
            Err(e) => {
                error!("Failed to receive packet: {}", e);
            }
        }
    }
}

fn get_network_interface(name: &str) -> Option<datalink::NetworkInterface> {
    let interfaces = datalink::interfaces();
    interfaces.into_iter().filter(|iface| iface.name == name).next()
}

fn get_device_ip(interface: &datalink::NetworkInterface) -> Option<Ipv4Addr> {
    for ip in &interface.ips {
        if let pnet::ipnetwork::IpNetwork::V4(ipv4) = ip {
            return Some(ipv4.ip());
        }
    }
    None
}

fn create_channel(interface: &datalink::NetworkInterface) -> Result<datalink::Channel, String> {
    // Enable promiscuous mode and set a larger buffer
    let mut config = datalink::Config::default();
    config.read_buffer_size = 65536;
    config.read_timeout = None;
    config.write_buffer_size = 65536;
    config.channel_type = pnet::datalink::ChannelType::Layer2; // <-- Use layer 2 for promiscuous mode

    match datalink::channel(interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => Ok(datalink::Channel::Ethernet(tx, rx)),
        Ok(_) => Err("Unhandled channel type".to_string()),
        Err(e) => Err(format!("Failed to create channel: {}", e)),
    }
}

fn process_packet(
    ethernet: &EthernetPacket,
    seen_ports: &mut HashMap<Ipv4Addr, HashSet<u16>>,
    _whitelist: &Vec<Ipv4Addr>,
    _ip_ranges: &Vec<std::ops::RangeInclusive<Ipv4Addr>>,
    alert_counts: &mut AlertCount,
    alert_tx: &mpsc::Sender<ui::Alert>,
) {
    log::debug!("Captured packet: {:?}", ethernet); // <-- Add debug logging
    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
        let source_ip = ipv4_packet.get_source();
        let dest_ip = ipv4_packet.get_destination();

        // Only process packets targeting our device
        if !is_our_device(&dest_ip) {
            return;
        }

        // Update total packet count for statistics
        if let Ok(mut contexts) = SCAN_CONTEXTS.try_lock() {
            let context = contexts.entry(source_ip)
                .or_insert_with(|| ScanContext {
                    first_seen: Instant::now(),
                    port_count: 0,
                    consecutive_hits: 0,
                    last_port: 0,
                    last_ack_alert: Instant::now(),
                    last_scan_type: None,
                });

            // Reset context if time window expired
            if context.first_seen.elapsed().as_secs() > SCAN_TIME_WINDOW {
                *context = ScanContext {
                    first_seen: Instant::now(),
                    port_count: 0,
                    consecutive_hits: 0,
                    last_port: 0,
                    last_ack_alert: Instant::now(),
                    last_scan_type: None,
                };
            }

            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                let flags = tcp_packet.get_flags();
                let port = tcp_packet.get_destination();

                // Analyze port sequence with error checking
                if context.last_port != 0 {
                    if (port as i32 - context.last_port as i32).abs() < 10 {
                        context.consecutive_hits = context.consecutive_hits.saturating_add(1);
                    } else {
                        context.consecutive_hits = 0;
                    }
                }
                context.last_port = port;

                // Rest of packet processing...
                process_tcp_packet(
                    tcp_packet, 
                    flags,
                    source_ip,
                    dest_ip,
                    port,
                    context,
                    seen_ports,
                    alert_counts,
                    alert_tx
                );
            }
        }
    }
}

// Add this helper function to check if an IP belongs to our device
fn is_our_device(ip: &Ipv4Addr) -> bool {
    // Get all interfaces
    let interfaces = datalink::interfaces();
    
    // Check if the IP matches any of our interface IPs
    for iface in interfaces {
        for ip_network in iface.ips {
            if let pnet::ipnetwork::IpNetwork::V4(ipv4_net) = ip_network {
                if ipv4_net.ip() == *ip {
                    return true;
                }
            }
        }
    }
    false
}

// Define valid scan types
const VALID_SCAN_TYPES: [&str; 6] = ["SYN", "FIN", "XMAS", "NULL", "ACK", "WINDOW"];

fn detect_scan_type(tcp_packet: &TcpPacket, flags: u16) -> Option<&'static str> {
    // More precise flag checking
    match flags {
        f if f == tcp::TcpFlags::SYN => Some("SYN"),
        f if f == tcp::TcpFlags::FIN => Some("FIN"),
        f if f == (tcp::TcpFlags::FIN | tcp::TcpFlags::PSH | tcp::TcpFlags::URG) => Some("XMAS"),
        0 => Some("NULL"),
        f if f == tcp::TcpFlags::ACK => Some("ACK"),
        _ if is_nmap_window_signature(tcp_packet) => Some("WINDOW"),
        _ => None,
    }
}

fn process_tcp_packet(
    tcp_packet: TcpPacket,
    flags: u16,
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    port: u16,
    context: &mut ScanContext,
    seen_ports: &mut HashMap<Ipv4Addr, HashSet<u16>>,
    alert_counts: &mut AlertCount,
    alert_tx: &mpsc::Sender<ui::Alert>,
) {
    // Update port count with duplicate protection
    let ports = seen_ports.entry(source_ip).or_insert_with(HashSet::new);
    if ports.insert(port) {
        context.port_count = context.port_count.saturating_add(1);
    }

    // Detect scans with improved accuracy and rate limiting
    if context.port_count > MIN_PORTS_FOR_SCAN && 
       context.consecutive_hits >= CONSECUTIVE_ALERTS {
        if should_alert(&source_ip, alert_counts) {
            send_scan_alert(
                alert_tx,
                "PORT_SCAN",
                &source_ip,
                &dest_ip,
                port,
                context.port_count,
            );
        }
    }

    // Only process known scan types with rate limiting
    if let Some(scan_type) = detect_scan_type(&tcp_packet, flags) {
        if VALID_SCAN_TYPES.contains(&scan_type) && 
           context.consecutive_hits >= CONSECUTIVE_ALERTS {
            
            // Special handling for ACK scans
            if scan_type == "ACK" {
                if context.last_ack_alert.elapsed() < ACK_SCAN_COOLDOWN {
                    return; // Skip this alert if we recently reported an ACK scan
                }
                
                // Only alert if this is a new port range
                if let Some(last_type) = &context.last_scan_type {
                    if last_type == "ACK" && 
                       (port as i32 - context.last_port as i32).abs() < MIN_PORT_DIFFERENCE {
                        return;
                    }
                }
                
                context.last_ack_alert = Instant::now();
            }

            // Update last scan type
            context.last_scan_type = Some(scan_type.to_string());
            
            if should_alert(&source_ip, alert_counts) {
                send_scan_alert(
                    alert_tx,
                    scan_type,
                    &source_ip,
                    &dest_ip,
                    port,
                    context.port_count,
                );
            }
        }
    }
}

fn send_scan_alert(
    alert_tx: &mpsc::Sender<ui::Alert>,
    scan_type: &str,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
    port: u16,
    port_count: usize,
) {
    let (alert_type, details) = match scan_type {
        "ACK" => (
            "NMAP_ACK_SCAN".to_string(),
            format!("ACK port scan detected on port range near {} (source: {})", 
                port, source_ip)
        ),
        "PORT_SCAN" => (
            "PORT_SCAN".to_string(),
            format!("Port scan detected: {} → {} ({} ports)", 
                source_ip, dest_ip, port_count)
        ),
        scan_type => (
            format!("NMAP_{}_SCAN", scan_type),
            format!("{} scan detected: {} → {} (Port {})", 
                scan_type, source_ip, dest_ip, port)
        ),
    };

    let alert = ui::Alert {
        timestamp: Utc::now(),
        alert_type,
        source_ip: source_ip.to_string(),
        details,
        severity: "HIGH".to_string(),
    };
    
    let _ = alert_tx.send(alert);
}

fn is_nmap_window_signature(tcp_packet: &TcpPacket) -> bool {
    let window = tcp_packet.get_window();
    window == 1024 || window == 2048 || window == 3072 ||
    window == 29200 || window == 65535
}

#[allow(dead_code)]
fn is_nmap_scan(tcp_packet: &TcpPacket, flags: u16) -> bool {
    // Improved Nmap scan patterns
    let is_syn_scan = flags == tcp::TcpFlags::SYN;
    let is_fin_scan = flags == tcp::TcpFlags::FIN;
    let is_xmas_scan = flags == (tcp::TcpFlags::FIN | tcp::TcpFlags::PSH | tcp::TcpFlags::URG);
    let is_null_scan = flags == 0;
    let is_ack_scan = flags == tcp::TcpFlags::ACK;

    // Additional Nmap fingerprints - relax window size requirements
    let is_nmap_window = tcp_packet.get_window() == 1024 || 
                        tcp_packet.get_window() == 2048 || 
                        tcp_packet.get_window() == 3072 ||
                        tcp_packet.get_window() == 29200 ||  // Common Nmap window size
                        tcp_packet.get_window() == 65535;    // Full window size used by some scans

    is_syn_scan || is_fin_scan || is_xmas_scan || is_null_scan || is_ack_scan ||
    is_nmap_window
}

#[allow(dead_code)]
fn is_nmap_response(tcp_packet: &TcpPacket) -> bool {
    // Check if this is a response to a scan
    // Responses typically have the ACK flag set and come from common ports
    tcp_packet.get_flags() & tcp::TcpFlags::ACK != 0 && 
    is_common_event(&Ipv4Addr::new(0, 0, 0, 0), tcp_packet.get_source())
}

#[allow(dead_code)]
fn is_whitelisted(ip: &Ipv4Addr, whitelist: &Vec<Ipv4Addr>, ip_ranges: &Vec<std::ops::RangeInclusive<Ipv4Addr>>) -> bool {
    // Check local network devices more carefully
    if is_local_network(ip) && !is_known_local_service(ip) {
        return false;  // Don't whitelist unknown local IPs
    }

    // Only whitelist specific IPs, not entire ranges for local network
    if whitelist.contains(ip) {
        return true;
    }

    // Only check cloud service ranges
    for range in ip_ranges {
        if ip >= range.start() && ip <= range.end() {
            let first_octet = ip.octets()[0];
            // Only whitelist known cloud providers
            match first_octet {
                52 | 17 | 20 | 104 | 172 => return true,
                _ => {}
            }
        }
    }

    false
}

fn is_local_network(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // Check for private IP ranges (RFC 1918)
    octets[0] == 10 || // 10.0.0.0/8
    (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) || // 172.16.0.0/12
    (octets[0] == 192 && octets[1] == 168) // 192.168.0.0/16
}

fn is_known_local_service(ip: &Ipv4Addr) -> bool {
    // Add your known local services here
    let known_services = [
        Ipv4Addr::new(192, 168, 1, 1),   // Router
        Ipv4Addr::new(192, 168, 1, 2),   // DNS
        // Add more known services
    ];
    known_services.contains(ip)
}

#[allow(dead_code)]
fn is_common_event(_ip: &Ipv4Addr, port: u16) -> bool {
    // Common ports to ignore
    let common_ports = [
        20, 21,   // FTP
        22,       // SSH
        23,       // Telnet
        25,       // SMTP
        53,       // DNS
        67, 68,   // DHCP
        80, 443,  // HTTP(S)
        110,      // POP3
        123,      // NTP
        137, 138, 139, // NetBIOS
        143,      // IMAP
        161, 162, // SNMP
        389,      // LDAP
        445,      // SMB
        465,      // SMTPS
        500,      // IKE
        514,      // Syslog
        587,      // SMTP Submission
        631,      // IPP (Printing)
        993,      // IMAPS
        995,      // POP3S
        1194,     // OpenVPN
        1433,     // MSSQL
        1521,     // Oracle
        3306,     // MySQL
        3389,     // RDP
        5432,     // PostgreSQL
        5900,     // VNC
        8080,     // HTTP Alternate
        8443,     // HTTPS Alternate
        9100,     // Printer
    ];

    common_ports.contains(&port)
}

fn should_alert(source_ip: &Ipv4Addr, alert_counts: &mut AlertCount) -> bool {
    let now = Instant::now();
    let (count, last_alert) = alert_counts
        .entry(*source_ip)
        .or_insert((0, now));
    
    if last_alert.elapsed() > ALERT_COOLDOWN {
        *count = 1;
        *last_alert = now;
        return true;
    }

    *count += 1;
    if *count >= ALERT_THRESHOLD {
        *count = 0;
        *last_alert = now;
        return true;
    }
    
    false
}