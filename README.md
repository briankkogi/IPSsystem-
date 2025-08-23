# IDS Project

This project is an Intrusion Detection System (IDS) designed to monitor network traffic and detect potential ransomware attacks. It captures network packets, analyzes them, and provides alerts for suspicious activities.

## Features

- Real-time network traffic capture and analysis
- Detection of various types of network scans (e.g., SYN, FIN, XMAS, NULL, ACK, WINDOW)
- User interface for monitoring alerts and inspecting network packets
- Logging of detected threats

## Requirements

- Rust (latest stable version)
- Cargo (Rust package manager)

## Dependencies

The project uses the following Rust crates:

- `pnet` for packet capture
- `notify` for file system monitoring
- `tauri` for GUI (optional, for later phases)
- `log` for logging
- `simplelog` for easier logging setup
- `eframe` and `egui` for the user interface
- `chrono` for date and time handling
- `crossbeam-channel` for multi-threaded communication
- `once_cell` for thread-safe static initialization

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/briankkogi/IPSsystem-.git
    cd ids_ransomware_project
    ```

2. **Build the project:**

    ```sh
    cargo build --release
    ```

3. **Run the project:**

    ```sh
    cargo run
    ```

## Usage

1. **Select a network interface:**
   The application will list all available network interfaces. Choose the one you want to monitor.

2. **Monitor network traffic:**
   The application will capture and analyze network packets in real-time. Alerts for suspicious activities will be displayed in the "Alert Log" tab.

3. **Inspect network packets:**
   Switch to the "Network Inspector" tab to view detailed information about captured packets.

## Acknowledgements

- [pnet](https://github.com/libpnet/libpnet) for packet capture
- [egui](https://github.com/emilk/egui) for the user interface
- [simplelog](https://github.com/drakulix/simplelog.rs) for logging
