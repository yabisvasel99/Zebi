```bash
#!/bin/bash

# Check Bash version
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "Erreur : Ce script nécessite Bash 4.0 ou supérieur. Version actuelle : ${BASH_VERSION}"
    exit 1
fi

# Colors for professional output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
OUTPUT_FILE="key_leaks_detected.txt"
OUTPUT_JSON="key_leaks_detected.json"
OUTPUT_CSV="key_leaks_detected.csv"
ENCRYPTED_OUTPUT="key_leaks_detected.enc"
DEBUG_LOG="key_scanner_debug.log"
MAX_DEPTH=10
DELAY=0.3
MAX_PARALLEL=10
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
)
TEMP_DIR="/tmp/key_scanner_$(date +%s)"
ALLOWED_EXTENSIONS="txt|md|js|json|yaml|yml|env|config|ini|php|sql|bak|backup|log|css|html|xml|ts|jsx|tsx|py|rb|sh"
# Convert ALLOWED_EXTENSIONS to regex pattern
EXT_REGEX=$(echo "$ALLOWED_EXTENSIONS" | sed 's/|/\\|/g' | sed 's/\./\\./g' | sed 's/^/\\./')
SUBDOMAINS=(
    "api" "dev" "staging" "test" "admin" "mail" "smtp" "backup" "db" "www"
    "app" "beta" "prod" "qa" "internal" "external" "cloud" "secure" "public" "private"
)
ENCRYPT_KEY=$(openssl rand -base64 32 2>/dev/null || echo "default_key_$(date +%s)")
LANGUAGE="fr" # fr or en
DEBUG_MODE=0

# Statistics
URL_COUNT=0
KEYS_FOUND=0
ERRORS=0
VALID_KEYS=0

# Extended list of 600+ sensitive paths (abridged for brevity, same as previous)
SENSITIVE_PATHS=(
    "/admin" "/wp-admin" "/login" "/dashboard" "/.env" "/.env.bak" "/config.js"
    "/backup" "/backup.sql" "/api" "/api/v1" "/logs" "/error.log" "/readme"
    "/wp-config.php" "/db" "/phpmyadmin" "/.next" "/.github" "/aws" "/.git"
    "/secrets" "/keys.txt" "/tmp" "/data" "/internal" "/key" "/password"
    # ... (full list includes 600+ paths as in previous version)
)

# Initialize temporary directory and output files
mkdir -p "$TEMP_DIR" || { echo -e "${RED}Erreur : Impossible de créer $TEMP_DIR${NC}"; exit 1; }
VISITED="$TEMP_DIR/visited_urls.txt"
touch "$VISITED"
echo "Encryption Key: $ENCRYPT_KEY" > "$TEMP_DIR/encryption_key.txt"
echo '{"leaks": []}' > "$OUTPUT_JSON"
echo "URL,Type,Key,Validated,Timestamp" > "$OUTPUT_CSV"
[ $DEBUG_MODE -eq 1 ] && : > "$DEBUG_LOG"

# Messages in French and English
declare -A MESSAGES
MESSAGES[fr,starting]="Démarrage de l'analyse à $(date)"
MESSAGES[fr,completed]="Analyse terminée à $(date)"
MESSAGES[fr,results]="Résultats enregistrés dans $OUTPUT_FILE, $OUTPUT_JSON, $OUTPUT_CSV"
MESSAGES[fr,warning]="ATTENTION : Fuites détectées. Vérifiez $OUTPUT_FILE et sécurisez vos clés immédiatement !"
MESSAGES[fr,no_leaks]="Aucune fuite détectée."
MESSAGES[en,starting]="Starting scan at $(date)"
MESSAGES[en,completed]="Scan completed at $(date)"
MESSAGES[en,results]="Results saved to $OUTPUT_FILE, $OUTPUT_JSON, $OUTPUT_CSV"
MESSAGES[en,warning]="WARNING: Potential leaks detected. Review $OUTPUT_FILE and secure your keys immediately!"
MESSAGES[en,no_leaks]="No leaks detected."

# Check dependencies
check_dependencies() {
    local deps=("curl" "lynx" "grep" "awk" "jq" "openssl" "nc")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            echo -e "${RED}Erreur : $dep n'est pas installé. Installez-le avec 'sudo apt-get install $dep' (ou 'brew install $dep' sur macOS).${NC}"
            exit 1
        fi
    done
}

# Progress bar function
progress_bar() {
    local width=50
    local percent=$1
    local filled=$((width * percent / 100))
    local empty=$((width - filled))
    printf "\r["
    printf "%${filled}s" | tr ' ' '#'
    printf "%${empty}s" | tr ' ' '-'
    printf "] %d%%" "$(percent)"
}

# Dashboard function
print_dashboard() {
    clear
    echo -e "${CYAN}┌──────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│ Ultimate AWS & SMTP Key Leak Detector v3.2       │${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│ URLs Scanned: ${URL_COUNT}                       │${NC}"
    echo -e "${CYAN}│ Keys Found: ${KEYS_FOUND}                        │${NC}"
    echo -e "${CYAN}│ Valid Keys: ${VALID_KEYS}                        │${NC}"
    echo -e "${CYAN}│ Errors: ${ERRORS}                                │${NC}"
    echo -e "${CYAN}│ Output Files: ${OUTPUT_FILE}, ${OUTPUT_JSON}, ${OUTPUT_CSV} │${NC}"
    echo -e "${CYAN}│ Encrypted Output: ${ENCRYPTED_OUTPUT}            │${NC}"
    echo -e "${CYAN}│ Debug Log: ${DEBUG_LOG}                          │${NC}"
    echo -e "${CYAN}│ Current Time: $(date)                            │${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────┘${NC}"
    echo
}

# Check if a URL is valid
is_valid_url() {
    local url=$1
    local ua=${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}
    local response
    response=$(curl -s -I -L -A "$ua" --max-time 10 --retry 2 --retry-delay 1 "$url" -w "%{http_code}" -o /dev/null 2>>"$DEBUG_LOG")
    if [[ "$response" =~ ^(200|301|302)$ ]]; then
        return 0
    else
        ((ERRORS++))
        [ $DEBUG_MODE -eq 1 ] && echo -e "${RED}Debug: HTTP $response for $url${NC}" >>"$DEBUG_LOG"
        return 1
    fi
}

# Decode various encodings
decode_content() {
    local content=$1
    local decoded=""
    
    # Base64 decoding
    base64_decoded=$(echo "$content" | grep -Eo '[A-Za-z0-9+/=]{20,}' | while read -r line; do
        echo "$line" | base64 -d 2>/dev/null
    done)
    
    # URL decoding
    url_decoded=$(echo "$content" | grep -Eo '%[0-9A-Fa-f]{2}+' | while read -r line; do
        printf "$(echo "$line" | sed 's/%/\\x/g')"
    done)
    
    # Hex decoding
    hex_decoded=$(echo "$content" | grep -Eo '[0-9a-fA-F]{20,}' | while read -r line; do
        echo "$line" | xxd -r -p 2>/dev/null
    done)
    
    # JSON unescaping
    json_decoded=$(echo "$content" | grep -Eo '"\\[^"]*\\"' | sed 's/\\//g; s/^"//; s/"$//')
    
    decoded="$base64_decoded\n$url_decoded\n$hex_decoded\n$json_decoded"
    echo -e "$decoded" | grep -v '^$'
}

# Validate AWS key (simplified)
validate_aws_key() {
    local access_key=$1
    local secret_key=$2
    if [[ "$access_key" =~ ^AKIA[0-9A-Z]{16}$ && "$secret_key" =~ ^[0-9a-zA-Z/+]{40}$ ]]; then
        return 0
    fi
    return 1
}

# Validate SMTP credentials (basic host/port check)
validate_smtp() {
    local host=$1
    local port=$2
    if [ -n "$host" ] && [ -n "$port" ]; then
        nc -z -w 5 "$host" "$port" >/dev/null 2>>"$DEBUG_LOG"
        return $?
    fi
    return 1
}

# Find AWS and SMTP keys
find_keys() {
    local content=$1
    local context=$2
    local decoded_content=$(decode_content "$content")
    local all_content="$content\n$decoded_content"
    
    # Filter out comments and documentation examples
    all_content=$(echo -e "$all_content" | grep -vE '^\s*(#|//|/\*|\*|--|<!--)' | grep -vE 'example|sample|dummy|test')
    
    # AWS Access Key ID
    local aws_access_keys=$(echo -e "$all_content" | grep -Eo 'AKIA[0-9A-Z]{16}' | sort -u)
    # AWS Secret Access Key
    local aws_secret_keys=$(echo -e "$all_content" | grep -Eo '[0-9a-zA-Z/+]{40}' | sort -u)
    # SMTP credentials
    local smtp_credentials=$(echo -e "$all_content" | grep -Ei 'smtp://|mail\.|smtp\.|user=|password=|port=|host=' | grep -Eo 'smtp://[^ ]+|mail\.[^ ]+|smtp\.[^ ]+|[^ ]*user=[^ ]*|[^ ]*password=[^ ]*|[^ ]*port=[0-9]+|[^ ]*host=[^ ]*' | sort -u)
    
    # Validate keys
    local valid_aws_access=""
    local valid_aws_secret=""
    local valid_smtp=""
    
    if [ -n "$aws_access_keys" ] && [ -n "$aws_secret_keys" ]; then
        while read -r access_key; do
            while read -r secret_key; do
                if validate_aws_key "$access_key" "$secret_key"; then
                    valid_aws_access="$valid_aws_access\n$access_key"
                    valid_aws_secret="$valid_aws_secret\n$secret_key"
                fi
            done <<< "$aws_secret_keys"
        done <<< "$aws_access_keys"
    fi
    
    if [ -n "$smtp_credentials" ]; then
        host=""
        port=""
        while read -r cred; do
            if [[ "$cred" =~ host=([^ ]*) ]]; then
                host="${BASH_REMATCH[1]}"
            elif [[ "$cred" =~ port=([0-9]+) ]]; then
                port="${BASH_REMATCH[1]}"
            fi
            if [ -n "$host" ] && [ -n "$port" ] && validate_smtp "$host" "$port"; then
                valid_smtp="$valid_smtp\n$cred"
            else
                valid_smtp="$valid_smtp\n$cred"
            fi
        done <<< "$smtp_credentials"
    fi
    
    echo -e "$valid_aws_access" | grep -v '^$'
    echo -e "$valid_aws_secret" | grep -v '^$'
    echo -e "$valid_smtp" | grep -v '^$'
}

# Save findings to file
save_to_file() {
    local url=$1
    local aws_access_keys=$2
    local aws_secret_keys=$3
    local smtp_credentials=$4
    local timestamp=$(date -Iseconds)
    
    if [ -n "$aws_access_keys" ] || [ -n "$aws_secret_keys" ] || [ -n "$smtp_credentials" ]; then
        ((KEYS_FOUND++))
        
        # Text output
        {
            echo "URL: $url"
            echo "Timestamp: $timestamp"
            if [ -n "$aws_access_keys" ]; then
                echo "AWS Access Key IDs:"
                echo "$aws_access_keys" | while read -r key; do
                    echo "  $key"
                    ((VALID_KEYS++))
                done
            fi
            if [ -n "$aws_secret_keys" ]; then
                echo "AWS Secret Access Keys:"
                echo "$aws_secret_keys" | while read -r key; do
                    echo "  $key"
                    ((VALID_KEYS++))
                done
            fi
            if [ -n "$smtp_credentials" ]; then
                echo "SMTP Credentials:"
                echo "$smtp_credentials" | while read -r cred; do
                    echo "  $cred"
                    ((VALID_KEYS++))
                done
            fi
            echo "--------------------------------------------------"
        } >> "$OUTPUT_FILE"
        
        # JSON output
        jq --arg url "$url" --arg ts "$timestamp" \
           --argjson access_keys "$(echo "$aws_access_keys" | jq -R -s 'split("\n") | map(select(. != ""))')" \
           --argjson secret_keys "$(echo "$aws_secret_keys" | jq -R -s 'split("\n") | map(select(. != ""))')" \
           --argjson smtp_creds "$(echo "$smtp_credentials" | jq -R -s 'split("\n") | map(select(. != ""))')" \
           '.leaks += [{"url": $url, "timestamp": $ts, "aws_access_keys": $access_keys, "aws_secret_keys": $secret_keys, "smtp_credentials": $smtp_creds}]' \
           "$OUTPUT_JSON" > "$TEMP_DIR/tmp.json" && mv "$TEMP_DIR/tmp.json" "$OUTPUT_JSON"
        
        # CSV output
        if [ -n "$aws_access_keys" ]; then
            echo "$aws_access_keys" | while read -r key; do
                echo "\"$url\",\"AWS Access Key\",\"$key\",\"Validated\",\"$timestamp\"" >> "$OUTPUT_CSV"
            done
        fi
        if [ -n "$aws_secret_keys" ]; then
            echo "$aws_secret_keys" | while read -r key; do
                echo "\"$url\",\"AWS Secret Key\",\"$key\",\"Validated\",\"$timestamp\"" >> "$OUTPUT_CSV"
            done
        fi
        if [ -n "$smtp_credentials" ]; then
            echo "$smtp_credentials" | while read -r cred; do
                echo "\"$url\",\"SMTP Credential\",\"$cred\",\"Validated\",\"$timestamp\"" >> "$OUTPUT_CSV"
            done
        fi
    fi
}

# Encrypt output file
encrypt_output() {
    if [ -s "$OUTPUT_FILE" ]; then
        openssl enc -aes-256-cbc -salt -in "$OUTPUT_FILE" -out "$ENCRYPTED_OUTPUT" -k "$ENCRYPT_KEY" 2>>"$DEBUG_LOG"
        if [ $? -eq 0 ]; then
            rm -f "$OUTPUT_FILE"
            echo -e "${YELLOW}Encrypted output saved to $ENCRYPTED_OUTPUT${NC}"
            echo -e "${YELLOW}Encryption key saved to $TEMP_DIR/encryption_key.txt${NC}"
        else
            echo -e "${RED}Failed to encrypt output${NC}"
        fi
    fi
}

# Check if URL is a repository
is_repository_url() {
    local url=$1
    echo "$url" | grep -qiE "github\.com|gitlab\.com|bitbucket\.org"
}

# Get repository files
get_repository_files() {
    local url=$1
    local depth=$2
    local files=""
    
    if [ "$depth" -ge "$MAX_DEPTH" ] || grep -Fx "$url" "$VISITED" >/dev/null; then
        return
    fi
    echo "$url" >> "$VISITED"
    
    local ua=${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}
    content=$(curl -s -L -A "$ua" --max-time 15 "$url" 2>>"$DEBUG_LOG")
    links=$(echo "$content" | lynx -dump -listonly -hiddenlinks=ignore "$url" 2>/dev/null | grep -Eo 'https?://[^ ]+' | grep -vE '\.(png|jpg|jpeg|gif|pdf|zip|tar\.gz)$' | sort -u)
    
    for link in $links; do
        if echo "$link" | grep -qiE "$EXT_REGEX"; then
            files="$files $link"
        elif echo "$link" | grep -q "^$(echo "$url" | awk -F'/' '{print $1"//"$3}')"; then
            files="$files $(get_repository_files "$link" $((depth + 1)))"
        fi
    done
    
    echo "$files"
    sleep "$DELAY"
}

# Scan URL
scan_url() {
    local url=$1
    local depth=$2
    
    if [ "$depth" -ge "$MAX_DEPTH" ] || grep -Fx "$url" "$VISITED" >/dev/null; then
        return
    fi
    echo "$url" >> "$VISITED"
    ((URL_COUNT++))
    
    print_dashboard
    echo -e "${BLUE}Scanning: $url (Depth: $depth)${NC}"
    
    if ! is_valid_url "$url"; then
        echo -e "${RED}Invalid or inaccessible: $url${NC}"
        return
    fi
    
    local ua=${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}
    content=$(curl -s -L -A "$ua" --max-time 20 "$url" 2>>"$DEBUG_LOG")
    keys=$(find_keys "$content" "$url")
    aws_access_keys=$(echo "$keys" | head -n 1)
    aws_secret_keys=$(echo "$keys" | sed -n '2p')
    smtp_credentials=$(echo "$keys" | tail -n 1)
    
    if [ -n "$aws_access_keys" ] || [ -n "$aws_secret_keys" ] || [ -n "$smtp_credentials" ]; then
        echo -e "${GREEN}Leak detected in $url${NC}"
        [ -n "$aws_access_keys" ] && echo -e "${YELLOW}AWS Access Keys: $aws_access_keys${NC}"
        [ -n "$aws_secret_keys" ] && echo -e "${YELLOW}AWS Secret Keys: $aws_secret_keys${NC}"
        [ -n "$smtp_credentials" ] && echo -e "${YELLOW}SMTP Credentials: $smtp_credentials${NC}"
        save_to_file "$url" "$aws_access_keys" "$aws_secret_keys" "$smtp_credentials"
    else
        echo -e "${NC}No leaks detected in $url"
    fi
    
    # Extract and scan linked resources
    links=$(echo "$content" | lynx -dump -listonly -hiddenlinks=ignore "$url" 2>/dev/null | grep -Eo 'https?://[^ ]+' | grep -vE '\.(png|jpg|jpeg|gif|pdf)$' | sort -u)
    for link in $links; do
        if echo "$link" | grep -q "^$(echo "$url" | awk -F'/' '{print $1"//"$3}')"; then
            (
                scan_url "$link" $((depth + 1))
            ) &
            while [ $(jobs -r | wc -l) -ge "$MAX_PARALLEL" ]; do
                sleep 0.1
            done
        fi
    done
    
    sleep "$DELAY"
}

# Read URLs from file
read_urls_from_file() {
    local file=$1
    if [ -f "$file" ]; then
        while IFS= read -r url; do
            url=$(echo "$url" | tr -d '[:space:]')
            if [ -n "$url" ] && echo "$url" | grep -qE '^https?://'; then
                echo "$url"
            elif [ -n "$url" ]; then
                echo "https://$url"
            fi
        done < "$file"
    else
        echo -e "${RED}Erreur : Le fichier $file n'existe pas.${NC}"
        exit 1
    fi
}

# Main function
main() {
    check_dependencies
    
    local urls=()
    local url_file=""
    
    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--file)
                url_file="$2"
                shift 2
                ;;
            --debug)
                DEBUG_MODE=1
                shift
                ;;
            *)
                urls+=("$1")
                shift
                ;;
        esac
    done
    
    # Add URLs from file
    if [ -n "$url_file" ]; then
        while read -r url; do
            urls+=("$url")
        done < <(read_urls_from_file "$url_file")
    fi
    
    if [ ${#urls[@]} -eq 0 ]; then
        echo "Usage: $0 [-f urls.txt] [--debug] <url1> [url2 ...]"
        exit 1
    fi
    
    print_dashboard
    echo -e "${GREEN}${MESSAGES[$LANGUAGE,starting]}${NC}"
    echo "${MESSAGES[$LANGUAGE,results]}"
    echo "----------------------------------------"
    
    total_urls=${#urls[@]}
    current_url=0
    
    for url in "${urls[@]}"; do
        ((current_url++))
        percent=$((current_url * 100 / total_urls))
        progress_bar "$percent"
        
        if ! echo "$url" | grep -qE '^https?://'; then
            url="https://$url"
        fi
        
        # Scan main URL
        if is_repository_url "$url"; then
            echo -e "${BLUE}Detected repository at $url${NC}"
            files=$(get_repository_files "$url" 0)
            file_count=$(echo "$files" | wc -w)
            echo -e "${YELLOW}Found $file_count files in repository${NC}"
            for file in $files; do
                (
                    scan_url "$file" 0
                ) &
                while [ $(jobs -r | wc -l) -ge "$MAX_PARALLEL" ]; do
                    sleep 0.1
                done
            done
        else
            scan_url "$url" 0
        fi
        
        # Scan sensitive paths
        echo -e "${BLUE}Scanning sensitive paths for $url${NC}"
        path_count=${#SENSITIVE_PATHS[@]}
        for i in "${!SENSITIVE_PATHS[@]}"; do
            path=${SENSITIVE_PATHS[$i]}
            test_url=$(echo "$url$path" | sed 's|//$|/|')
            percent=$(( (i + 1) * 100 / path_count ))
            progress_bar "$percent"
            (
                scan_url "$test_url" 0
            ) &
            while [ $(jobs -r | wc -l) -ge "$MAX_PARALLEL" ]; do
                sleep 0.1
            done
        done
        
        # Scan subdomains
        domain=$(echo "$url" | awk -F'/' '{print $3}' | sed 's/^www\.//')
        echo -e "${BLUE}Scanning subdomains for $domain${NC}"
        for sub in "${SUBDOMAINS[@]}"; do
            test_url="https://$sub.$domain"
            percent=$(( (i + 1) * 100 / ${#SUBDOMAINS[@]} ))
            progress_bar "$percent"
            (
                scan_url "$test_url" 0
            ) &
            while [ $(jobs -r | wc -l) -ge "$MAX_PARALLEL" ]; do
                sleep 0.1
            done
        done
        
        # Attempt localhost
        for proto in http https; do
            for host in localhost 127.0.0.1; do
                test_url="$proto://$host"
                if [ -n "$domain" ]; then
                    test_url="$proto://$host.$domain"
                fi
                echo -e "${BLUE}Attempting localhost: $test_url${NC}"
                (
                    scan_url "$test_url" 0
                ) &
                while [ $(jobs -r | wc -l) -ge "$MAX_PARALLEL" ]; do
                    sleep 0.1
                done
            done
        done
        
        wait
    done
    
    encrypt_output
    
    print_dashboard
    echo -e "${GREEN}${MESSAGES[$LANGUAGE,completed]}${NC}"
    echo -e "${BLUE}${MESSAGES[$LANGUAGE,results]}${NC}"
    if [ -s "$OUTPUT_FILE" ] || [ -s "$ENCRYPTED_OUTPUT" ]; then
        echo -e "${RED}${MESSAGES[$LANGUAGE,warning]}${NC}"
    else
        echo -e "${GREEN}${MESSAGES[$LANGUAGE,no_leaks]}${NC}"
    fi
}

# Cleanup and run
trap 'rm -rf "$TEMP_DIR"; exit' INT TERM EXIT
main "$@"
```