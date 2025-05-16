#!/bin/bash

# Colors for professional output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
OUTPUT_FILE="key_leaks_detected.txt"
MAX_DEPTH=7
DELAY=0.5
USER_AGENT="Mozilla/5.0 (compatible; KeyScanner/2.0)"
TEMP_DIR="/tmp/key_scanner_$(date +%s)"
ALLOWED_EXTENSIONS="txt|md|js|json|yaml|yml|env|config|ini|php|sql|bak|backup|log|css|html|xml"
SUBDOMAINS=("api" "dev" "staging" "test" "admin" "mail" "smtp" "backup" "db" "www")

# Statistics
URL_COUNT=0
KEYS_FOUND=0
ERRORS=0

# Extended list of 500+ sensitive paths
SENSITIVE_PATHS=(
    # Admin paths
    "/admin" "/wp-admin" "/login" "/dashboard" "/administrator" "/controlpanel" "/cpanel"
    "/admin/login" "/admin/index.php" "/adminpanel" "/admin_area" "/admin-login"
    "/admin/login.php" "/admin/login.html" "/admin/dashboard" "/admin/settings"
    "/adm" "/adm/login" "/adm/index.php" "/admin1" "/admin2" "/admin3"
    "/admin4" "/admin5" "/moderator" "/manager" "/management" "/sysadmin"
    "/console" "/webadmin" "/admin-console" "/admin-portal" "/backoffice"

    # Configuration files
    "/.env" "/.env.bak" "/.env.example" "/.env.local" "/.env.prod" "/.env.dev"
    "/config.js" "/config.json" "/settings.py" "/config.yaml" "/config.yml"
    "/app.config" "/web.config" "/application.properties" "/settings.json"
    "/secrets.json" "/keys.json" "/credentials.json" "/access.json"
    "/.aws/credentials" "/.aws/config" "/aws.json" "/aws.yml"
    "/.npmrc" "/.yarnrc" "/package.json" "/package-lock.json" "/composer.json"
    "/next.config.js" "/nuxt.config.js" "/gatsby-config.js" "/laravel" "/.env.testing"
    "/database.yml" "/dbconfig.php" "/config.inc.php" "/settings.php" "/init.php"

    # Backup files
    "/backup" "/backup.sql" "/backup.zip" "/backup.tar.gz" "/backup.bak"
    "/db_backup.sql" "/database.sql" "/site_backup.zip" "/wp-content/backup"
    "/backups" "/backups/db.sql" "/backups/site.tar.gz" "/old" "/archive"
    "/dump.sql" "/data.sql" "/backup.gz" "/backup.rar" "/site.bak"

    # API and sensitive endpoints
    "/api" "/api/v1" "/api/v2" "/api/keys" "/api/config" "/api/credentials"
    "/api/secrets" "/rest" "/rest/api" "/graphql" "/api/admin" "/api/settings"
    "/.well-known" "/.well-known/security.txt" "/security.txt" "/endpoints"
    "/api/auth" "/api/token" "/api/oauth" "/api/webhook" "/api/debug"

    # Logs and debug
    "/logs" "/log" "/error.log" "/access.log" "/debug.log" "/php_errors.log"
    "/debug" "/debug.php" "/phpinfo" "/phpinfo.php" "/info.php" "/test.php"
    "/test" "/test.html" "/test.txt" "/dev" "/dev/test" "/staging"
    "/trace.log" "/app.log" "/server.log" "/nginx.log" "/apache.log"

    # Common files
    "/readme" "/README.md" "/license" "/LICENSE.txt" "/changelog" "/CHANGELOG.md"
    "/robots.txt" "/sitemap.xml" "/humans.txt" "/.gitignore" "/.gitconfig"
    "/.htaccess" "/.htpasswd" "/server-status" "/status" "/health"
    "/manifest.json" "/sw.js" "/favicon.ico" "/crossdomain.xml" "/clientaccesspolicy.xml"

    # CMS-specific
    "/wp-config.php" "/wp-content" "/wp-includes" "/wp-json" "/wordpress"
    "/drupal" "/joomla" "/magento" "/prestashop" "/opencart"
    "/craft" "/typo3" "/concrete5" "/modx" "/expressionengine"

    # Database
    "/db" "/database" "/dbadmin" "/phpmyadmin" "/pma" "/mysql" "/sql"
    "/adminer" "/adminer.php" "/db.php" "/database.yml" "/dbconfig.php"
    "/mongo" "/mongodb" "/postgres" "/pgadmin" "/redis"

    # Modern frameworks
    "/.next" "/.nuxt" "/.gatsby" "/.svelte" "/.vue" "/.react" "/.angular"
    "/build" "/dist" "/public" "/static" "/assets" "/src" "/app"
    "/pages" "/components" "/routes" "/middleware" "/plugins" "/utils"

    # DevOps and CI/CD
    "/.github" "/.github/workflows" "/.gitlab-ci.yml" "/.travis.yml" "/.circleci"
    "/Jenkinsfile" "/.drone.yml" "/.codecov.yml" "/.docker" "/.dockerignore"
    "/docker-compose.yml" "/Dockerfile" "/k8s" "/kubernetes" "/helm" "/charts"
    "/terraform" "/ansible" "/playbooks" "/roles" "/inventory" "/vars"

    # Other sensitive paths (expanded to 500+)
    "/.git" "/.git/HEAD" "/.git/config" "/.git/logs" "/.git/objects"
    "/.svn" "/.svn/entries" "/.hg" "/.hg/hgrc" "/.bzr" "/.bzr/branch"
    "/keys" "/keys.txt" "/secrets" "/secrets.txt" "/credentials" "/creds"
    "/private" "/private.key" "/public.key" "/auth" "/auth.json" "/auth.yaml"
    "/token" "/tokens.json" "/oauth" "/api_token" "/api_key" "/access_key"
    "/install" "/install.php" "/setup" "/setup.php" "/config.php"
    "/configuration.php" "/core" "/core/config" "/core/settings" "/lib"
    "/lib/config" "/src/config" "/src/keys" "/vendor" "/vendor/config"
    "/tmp" "/temp" "/cache" "/cache/config" "/cache/keys" "/data"
    "/data/config" "/data/keys" "/storage" "/storage/logs" "/uploads"
    "/files" "/file" "/documents" "/doc" "/docs" "/system" "/system/config"
    "/system/keys" "/internal" "/hidden" "/protected" "/secure" "/security"
    "/conf" "/etc" "/etc/config" "/var" "/var/log" "/var/www" "/home"
    "/home/config" "/root" "/root/config" "/opt" "/opt/config" "/usr"
    "/usr/local" "/usr/local/config" "/key" "/key.txt" "/secret.txt"
    "/password" "/passwords.txt" "/pass" "/pass.txt" "/cred.txt" "/creds.txt"
    "/access" "/access.txt" "/token.txt" "/.bashrc" "/.bash_profile" "/.zshrc"
    "/.profile" "/.ssh" "/.ssh/config" "/.ssh/id_rsa" "/.ssh/authorized_keys"
    "/cron" "/crontab" "/jobs" "/scheduled" "/tasks" "/maintenance" "/maint"
    "/upgrade" "/update" "/patch" "/version" "/version.txt" "/build.json"
    "/deploy" "/deploy.yml" "/release" "/releases" "/snapshot" "/snapshots"
    "/error" "/errors" "/exception" "/exceptions" "/stacktrace" "/trace"
    "/traces" "/monitor" "/monitoring" "/metrics" "/stats" "/statistics"
    "/analytics" "/reports" "/report" "/audit" "/audits" "/compliance"
    "/policy" "/policies" "/terms" "/privacy" "/disclaimer" "/legal" "/support"
    "/contact" "/feedback" "/help" "/faq" "/about" "/info" "/.vscode"
    "/.vscode/settings.json" "/.idea" "/.idea/workspace.xml" "/.editorconfig"
    "/.eslintrc" "/.prettierrc" "/tsconfig.json" "/webpack.config.js"
    "/gulpfile.js" "/gruntfile.js" "/makefile" "/.docker/config.json"
    "/.helm" "/pod" "/pods" "/service" "/services" "/deployment" "/deployments"
    "/ingress" "/configmap" "/statefulset" "/cronjob" "/job" "/replica"
    "/replicas" "/node" "/nodes" "/cluster" "/clusters" "/master" "/worker"
    "/etcd" "/consul" "/zookeeper" "/redis" "/memcached" "/mongodb" "/postgres"
    "/postgresql" "/mariadb" "/cassandra" "/elasticsearch" "/kibana" "/logstash"
    "/grafana" "/prometheus" "/alertmanager" "/vault" "/nomad" "/ansible"
    "/playbook" "/roles" "/tasks" "/inventory" "/group_vars" "/host_vars"
    "/defaults" "/meta" "/handlers" "/templates" "/modules" "/plugins"
    "/extensions" "/addons" "/themes" "/skins" "/layout" "/layouts" "/views"
    "/partials" "/components" "/widgets" "/blocks" "/elements" "/pages" "/posts"
    "/articles" "/blogs" "/news" "/updates" "/events" "/calendar" "/schedule"
    "/timeline" "/history" "/archives" "/sitemap" "/rss" "/atom" "/feed" "/feeds"
    "/xml" "/json" "/csv" "/tsv" "/export" "/import" "/migrate" "/migration"
    "/migrations" "/schema" "/schemas" "/model" "/models" "/entity" "/entities"
    "/table" "/tables" "/column" "/columns" "/index" "/indexes" "/constraint"
    "/constraints" "/trigger" "/triggers" "/procedure" "/procedures" "/function"
    "/functions" "/view" "/views" "/materialized" "/partition" "/partitions"
    "/backup" "/restore" "/recovery" "/replication" "/replica" "/primary"
    "/secondary" "/leader" "/follower" "/read" "/write" "/query" "/queries"
    "/search" "/filter" "/sort" "/group" "/aggregate" "/join" "/union"
    "/intersect" "/except" "/limit" "/offset" "/fetch" "/count" "/sum" "/avg"
    "/min" "/max" "/distinct" "/order" "/asc" "/desc" "/nulls" "/first" "/last"
    "/top" "/bottom" "/env" "/environment" "/prod" "/production" "/dev" "/test"
    "/qa" "/stage" "/uat" "/sandbox" "/local" "/cloud" "/aws" "/azure" "/gcp"
    "/serverless" "/lambda" "/functions" "/api_gateway" "/dynamodb" "/s3" "/ec2"
    "/rds" "/ecs" "/eks" "/fargate" "/cloudwatch" "/sns" "/sqs" "/eventbridge"
    "/stepfunctions" "/glue" "/athena" "/redshift" "/kinesis" "/firehose"
    "/cognito" "/iam" "/secretsmanager" "/kms" "/parameterstore" "/ssm"
)

# Initialize temporary directory
mkdir -p "$TEMP_DIR"
VISITED="$TEMP_DIR/visited_urls.txt"
touch "$VISITED"

# Progress bar function
progress_bar() {
    local width=50
    local percent=$1
    local filled=$((width * percent / 100))
    local empty=$((width - filled))
    printf "\r["
    printf "%${filled}s" | tr ' ' '#'
    printf "%${empty}s" | tr ' ' '-'
    printf "] %d%%" "$percent"
}

# Dashboard function
print_dashboard() {
    clear
    echo -e "${CYAN}┌──────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│ AWS & SMTP Key Leak Detector v2.0                │${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│ URLs Scanned: ${URL_COUNT}                       │${NC}"
    echo -e "${CYAN}│ Keys Found: ${KEYS_FOUND}                        │${NC}"
    echo -e "${CYAN}│ Errors: ${ERRORS}                                │${NC}"
    echo -e "${CYAN}│ Output File: ${OUTPUT_FILE}                      │${NC}"
    echo -e "${CYAN}│ Current Time: $(date)                            │${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────┘${NC}"
    echo
}

# Check if a URL is valid
is_valid_url() {
    local url=$1
    local response
    response=$(curl -s -I -L -A "$USER_AGENT" --max-time 10 "$url" -w "%{http_code}" -o /dev/null)
    if [[ "$response" =~ ^(200|301|302)$ ]]; then
        return 0
    else
        ((ERRORS++))
        return 1
    fi
}

# Decode Base64 and URL-encoded strings
decode_content() {
    local content=$1
    local decoded=""
    
    # Try Base64 decoding
    base64_decoded=$(echo "$content" | grep -Eo '[A-Za-z0-9+/=]{20,}' | while read -r line; do
        echo "$line" | base64 -d 2>/dev/null
    done)
    
    # Try URL decoding
    url_decoded=$(echo "$content" | grep -Eo '%[0-9A-Fa-f]{2}' | while read -r line; do
        printf "$(echo "$line" | sed 's/%/\\x/g')"
    done)
    
    decoded="$base64_decoded\n$url_decoded"
    echo -e "$decoded" | grep -v '^$'
}

# Find AWS and SMTP keys
find_keys() {
    local content=$1
    local decoded_content=$(decode_content "$content")
    local all_content="$content\n$decoded_content"
    
    # AWS Access Key ID
    local aws_access_keys=$(echo -e "$all_content" | grep -Eo 'AKIA[0-9A-Z]{16}' | sort -u)
    # AWS Secret Access Key
    local aws_secret_keys=$(echo -e "$all_content" | grep -Eo '[0-9a-zA-Z/+]{40}' | sort -u)
    # SMTP credentials (host, user, password, port)
    local smtp_credentials=$(echo -e "$all_content" | grep -Ei 'smtp://|mail\.|smtp\.|user=|password=|port=|host=' | grep -Eo 'smtp://[^ ]+|mail\.[^ ]+|smtp\.[^ ]+|[^ ]*user=[^ ]*|[^ ]*password=[^ ]*|[^ ]*port=[0-9]+|[^ ]*host=[^ ]*' | sort -u)
    
    echo "$aws_access_keys" "$aws_secret_keys" "$smtp_credentials"
}

# Save findings to file
save_to_file() {
    local url=$1
    local aws_access_keys=$2
    local aws_secret_keys=$3
    local smtp_credentials=$4
    
    if [ -n "$aws_access_keys" ] || [ -n "$aws_secret_keys" ] || [ -n "$smtp_credentials" ]; then
        ((KEYS_FOUND++))
        echo "URL: $url" >> "$OUTPUT_FILE"
        if [ -n "$aws_access_keys" ]; then
            echo "AWS Access Key IDs:" >> "$OUTPUT_FILE"
            echo "$aws_access_keys" | while read -r key; do
                echo "  $key" >> "$OUTPUT_FILE"
            done
        fi
        if [ -n "$aws_secret_keys" ]; then
            echo "AWS Secret Access Keys:" >> "$OUTPUT_FILE"
            echo "$aws_secret_keys" | while read -r key; do
                echo "  $key" >> "$OUTPUT_FILE"
            done
        fi
        if [ -n "$smtp_credentials" ]; then
            echo "SMTP Credentials:" >> "$OUTPUT_FILE"
            echo "$smtp_credentials" | while read -r cred; do
                echo "  $cred" >> "$OUTPUT_FILE"
            done
        fi
        echo "--------------------------------------------------" >> "$OUTPUT_FILE"
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
    
    content=$(curl -s -L -A "$USER_AGENT" --max-time 10 "$url")
    links=$(echo "$content" | lynx -dump -listonly -hiddenlinks=ignore "$url" 2>/dev/null | grep -Eo 'https?://[^ ]+' | grep -vE '\.(png|jpg|jpeg|gif|pdf|zip|tar\.gz)$' | sort -u)
    
    for link in $links; do
        if echo "$link" | grep -qiE "\.($ALLOWED_EXTENSIONS)$"; then
            files="$files $link"
        elif echo "$link" | grep -q "^$(echo "$url" | awk -F'/' '{print $1"//"$3}')"; then
            files="$files $(get_repository_files "$link" $((depth + 1)))"
        fi
    done
    
    echo "$files"
    sleep $DELAY
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
    
    content=$(curl -s -L -A "$USER_AGENT" --max-time 15 "$url")
    keys=$(find_keys "$content")
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
    
    # Extract and scan linked resources (JS, CSS, etc.)
    links=$(echo "$content" | lynx -dump -listonly -hiddenlinks=ignore "$url" 2>/dev/null | grep -Eo 'https?://[^ ]+' | grep -vE '\.(png|jpg|jpeg|gif|pdf)$' | sort -u)
    for link in $links; do
        if echo "$link" | grep -q "^$(echo "$url" | awk -F'/' '{print $1"//"$3}')"; then
            scan_url "$link" $((depth + 1))
        fi
    done
    
    sleep $DELAY
}

# Main function
main() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <url1> [url2 ...]"
        exit 1
    fi
    
    print_dashboard
    echo -e "${GREEN}Starting scan at $(date)${NC}"
    echo "Results will be saved to $OUTPUT_FILE"
    echo "----------------------------------------"
    
    total_urls=$#
    current_url=0
    
    for url in "$@"; do
        ((current_url++))
        percent=$((current_url * 100 / total_urls))
        progress_bar $percent
        
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
                scan_url "$file" 0
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
            progress_bar $percent
            scan_url "$test_url" 0
        done
        
        # Scan subdomains
        domain=$(echo "$url" | awk -F'/' '{print $3}' | sed 's/^www\.//')
        echo -e "${BLUE}Scanning subdomains for $domain${NC}"
        for sub in "${SUBDOMAINS[@]}"; do
            test_url="https://$sub.$domain"
            percent=$(( (i + 1) * 100 / ${#SUBDOMAINS[@]} ))
            progress_bar $percent
            scan_url "$test_url" 0
        done
        
        # Attempt localhost
        for proto in http https; do
            for host in localhost 127.0.0.1; do
                test_url="$proto://$host"
                if [ -n "$domain" ]; then
                    test_url="$proto://$host.$domain"
                fi
                echo -e "${BLUE}Attempting localhost: $test_url${NC}"
                scan_url "$test_url" 0
            done
        done
    done
    
    print_dashboard
    echo -e "${GREEN}Scan completed at $(date)${NC}"
    echo -e "${BLUE}Results saved to $OUTPUT_FILE${NC}"
    if [ -s "$OUTPUT_FILE" ]; then
        echo -e "${RED}WARNING: Potential leaks detected. Review $OUTPUT_FILE and secure your keys immediately!${NC}"
    else
        echo -e "${GREEN}No leaks detected.${NC}"
    fi
}

# Cleanup and run
trap 'rm -rf "$TEMP_DIR"; exit' INT TERM EXIT
main "$@"