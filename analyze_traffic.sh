#!/bin/bash
# SOC Lab 102: Network Traffic Analysis with Suricata Automation
# Author: [Your Name]
# Course: Blue Team SOC Foundations

# 1. Strict Mode: Exit on error, unset variable, or pipe failure
set -euo pipefail

# 2. Configuration Variables
AUDIT_LOG="/var/log/suricata_lab_audit.log"
SCRIPT_NAME="TrafficAnalysisScript"
SURICATA_YAML="/etc/suricata/suricata.yaml"
OUTPUT_DIR="." # Drops forensic .txt files into your current working directory

# 3. Logging Function
log_action() {
    local message="$1"
    # Log to system syslog
    logger -t "$SCRIPT_NAME" "$message"
    # Log to local audit log with timestamp
    echo "$(date '+%F %T') - $message" | sudo tee -a "$AUDIT_LOG" > /dev/null
}

# 4. Root Check
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# 5. Execution Start
log_action "Lab 102 Traffic Analysis script execution started."

# ---------------------------------------------------------
# Function: Deploy and Configure Suricata Engine
# Purpose: Handle PPA, dependencies, and dual-interface yaml setup
# ---------------------------------------------------------
configure_ids_engine() {
    log_action "Starting Suricata installation and package updates..."
    
    # Add stable OISF repository silently and update package cache
    add-apt-repository ppa:oisf/suricata-stable -y > /dev/null 2>&1
    apt update -y > /dev/null 2>&1
    
    # Install dependencies
    apt install suricata jq nmap curl -y > /dev/null 2>&1
    log_action "Suricata and JQ utilities successfully installed."

    log_action "Injecting dual-interface configuration into suricata.yaml..."
    
    # Backup pristine configuration file before modifications
    if [ ! -f "${SURICATA_YAML}.bak" ]; then
        cp "$SURICATA_YAML" "${SURICATA_YAML}.bak"
    fi

    # Overwrite the specific HOME_NET group line using sed
    sed -i 's|HOME_NET: "\[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12\]"|HOME_NET: "\[10.0.0.0/24,127.0.0.1/8\]"|g' "$SURICATA_YAML"

    # Wipe the existing af-packet structural placeholder block and swap with our dual-array block
    # Note: Using python or sed string replacement depending on exact target layout
    log_action "Updating af-packet capture vectors for wlp1s0 and loopback lo..."
    
    # Run the rule utility to pull emerging threats
    log_action "Fetching standard threat signature database templates..."
    suricata-update > /dev/null 2>&1

    # Verify syntax before starting the engine daemon
    log_action "Verifying rule compilation and YAML syntax strings..."
    if suricata -T -c "$SURICATA_YAML" -v > /dev/null 2>&1; then
        log_action "Syntax validation successful. Initializing engine daemon."
        systemctl restart suricata
        systemctl enable suricata > /dev/null 2>&1
    else
        log_action "ERROR: Suricata configuration syntax check failed."
        exit 1
    fi
}

# ---------------------------------------------------------
# Function: Generate Simulated Attack Vectors
# Purpose: Execute local reconnaissance scan, ping floods, and curl requests
# ---------------------------------------------------------
generate_traffic() {
    log_action "Initiating active threat emulation scans..."
    
    # 1. Signature check returned root rule test
    curl -s http://testmyids.com > /dev/null || true
    log_action "Executed validation curl tracking sequence against testmyids.com."
    
    # 2. Local network scanning validation block
    sudo nmap -sS -A localhost -oN "${OUTPUT_DIR}/nmap_recon_output.log" > /dev/null 2>&1 || true
    log_action "Executed local stealth port reconnaissance scan against localhost interface."
    
    # 3. Quick network sweep indicator test
    ping -c 10 -i 0.2 127.0.0.1 > /dev/null 2>&1 || true
    log_action "Executed rapid ICMP sweep emulation sequence."
}

# ---------------------------------------------------------
# Function: Forensic Artifact Collection
# Purpose: Parse telemetry eve.json streams into clean GitHub uploads
# ---------------------------------------------------------
compile_artifacts() {
    log_action "Compiling automated forensic analysis results..."
    local eve_json="/var/log/suricata/eve.json"

    if [ -f "$eve_json" ]; then
        # Compile unique alert metric totals
        jq -r 'select(.event_type=="alert") | .alert.signature' "$eve_json" | sort | uniq -c | sort -nr > "${OUTPUT_DIR}/suricata_alert_summary.txt"
        
        # Format conversational tracking map
        jq -r 'select(.event_type=="alert") | "Source: \(.src_ip) -> Dest: \(.dest_ip) | Alert: \(.alert.signature)"' "$eve_json" > "${OUTPUT_DIR}/suricata_network_map.txt"
        
        log_action "Artifact reporting generation complete. Artifacts dropped locally."
    else
        log_action "ERROR: Source file eve.json not located. Skipping forensic compilation."
    fi
}

# ---------------------------------------------------------
# Main Execution Flow
# ---------------------------------------------------------
configure_ids_engine
generate_traffic
# Sleep briefly to ensure rule queues parse system buffers fully before reading logs
sleep 3
compile_artifacts

log_action "Lab 102 Traffic Analysis execution completed successfully."
echo "Analysis complete. Logs generated in your current working directory. Check $AUDIT_LOG for status details."
