#!/bin/bash
# entrypoint.sh

set -euo pipefail

function log_error() {
  local -r ERROR_TEXT="\033[0;31m"  # red
  local -r NO_COLOR="\033[0m"
  echo -e "${ERROR_TEXT}$1${NO_COLOR}" >&2
  echo "$1" >> "${FULL_LOG:-/dev/null}" # Log to FULL_LOG if defined, else discard
}

function run_step() {
  local -r msg="$1"
  shift 1
  echo "> ${msg}..."
  if "$@"; then
    echo "OK"
  else
    # Explicitly log the error if the command fails, as run_step suppresses default STDERR
    # from the command itself, and we want to see the docker connection error.
    local last_error_output=$(cat "${LAST_ERROR:-/dev/null}") # Capture last error if available
    if [[ -n "${last_error_output}" ]]; then
        log_error "${last_error_output}"
    fi
    log_error "FAILED: ${msg}"
    return $?
  fi
}

function get_random_port {
  local -i num=0
  until (( 1024 <= num && num < 65536)); do
    num=$(( RANDOM + (RANDOM % 2) * 32768 ));
  done;
  echo "${num}";
}

function safe_base64() {
  base64 -w 0 - | tr '/+' '_-' | sed 's/=//g'
}

function generate_secret_key() {
  SB_API_PREFIX="$(head -c 16 /dev/urandom | safe_base64)"
  export SB_API_PREFIX
}

function generate_certificate() {
  local -r STATE_DIR="${SHADOWBOX_DIR}/persisted-state"
  
  # Removed 'readonly'
  SB_CERTIFICATE_FILE="${STATE_DIR}/shadowbox-selfsigned.crt"
  SB_PRIVATE_KEY_FILE="${STATE_DIR}/shadowbox-selfsigned.key"
  
  export SB_CERTIFICATE_FILE
  export SB_PRIVATE_KEY_FILE

  declare -a openssl_req_flags=(
    -x509 -nodes -days 36500 -newkey rsa:4096 # Corrected to 4096 if that was the intent
    -subj "/CN=${PUBLIC_HOSTNAME}"
    -keyout "${SB_PRIVATE_KEY_FILE}" -out "${SB_CERTIFICATE_FILE}"
  )
  openssl req "${openssl_req_flags[@]}" >&2
}

function generate_certificate_fingerprint() {
  local -r STATE_DIR="${SHADOWBOX_DIR}/persisted-state"
  local -r SB_CERTIFICATE_FILE="${STATE_DIR}/shadowbox-selfsigned.crt" # Ensure path is correct

  local CERT_OPENSSL_FINGERPRINT
  CERT_OPENSSL_FINGERPRINT="$(openssl x509 -in "${SB_CERTIFICATE_FILE}" -noout -sha256 -fingerprint)" || return
  local CERT_HEX_FINGERPRINT
  CERT_HEX_FINGERPRINT="$(echo "${CERT_OPENSSL_FINGERPRINT#*=}" | tr -d :)" || return
  output_config "certSha256:${CERT_HEX_FINGERPRINT}"
}

function join() {
  local IFS="$1"
  shift
  echo "$*"
}

function write_config() {
  local -r STATE_DIR="${SHADOWBOX_DIR}/persisted-state"
  local -a config=()
  if (( ${FLAGS_KEYS_PORT:-0} != 0 )); then # Use default 0 if not set
    config+=("\"portForNewAccessKeys\": ${FLAGS_KEYS_PORT}")
  fi
  if [[ -n "${SB_DEFAULT_SERVER_NAME:-}" ]]; then
    config+=("\"name\": \"$(escape_json_string "${SB_DEFAULT_SERVER_NAME}")\"")   
  fi
  config+=("\"hostname\": \"$(escape_json_string "${PUBLIC_HOSTNAME}")\"")
  config+=("\"metricsEnabled\": ${SB_METRICS_ENABLED:-false}")
  echo "{$(join , "${config[@]}")}" > "${STATE_DIR}/shadowbox_server_config.json"
}

function start_shadowbox() {
  local -r STATE_DIR="${SHADOWBOX_DIR}/persisted-state"
  local -r START_SCRIPT="${STATE_DIR}/start_container.sh"

  # Add a small delay and check docker info for debugging
  echo "Checking Docker daemon connectivity..."
  sleep 2 # Give Docker some time
  docker info >/dev/null 2>&1 || { log_error "Docker daemon not accessible from inside container. Is it running on the host?"; return 1; }
  echo "Docker daemon reachable."

  cat <<-EOF > "${START_SCRIPT}"
# This script starts the Outline server container ("Shadowbox").
# If you need to customize how the server is run, you can edit this script, then restart with:
#
#     "${START_SCRIPT}"

set -eu

docker stop "${CONTAINER_NAME}" 2> /dev/null || true
docker rm -f "${CONTAINER_NAME}" 2> /dev/null || true

docker_command=(
  docker
  run
  -d
  --name "${CONTAINER_NAME}" --restart always --net host

  # Used by Watchtower to know which containers to monitor.
  --label 'com.centurylinklabs.watchtower.enable=true'
  
  # Use log rotation. See https://docs.docker.com/config/containers/logging/configure/.
  --log-driver local

  # The state that is persisted across restarts.
  -v "${STATE_DIR}:${STATE_DIR}"
    
  # Where the container keeps its persistent state.
  -e "SB_STATE_DIR=${STATE_DIR}"

  # Port number and path prefix used by the server manager API.
  -e "SB_API_PORT=${API_PORT}"
  -e "SB_API_PREFIX=${SB_API_PREFIX}"

  # Location of the API TLS certificate and key.
  -e "SB_CERTIFICATE_FILE=${SB_CERTIFICATE_FILE}"
  -e "SB_PRIVATE_KEY_FILE=${SB_PRIVATE_KEY_FILE}"

  # Where to report metrics to, if opted-in.
  -e "SB_METRICS_URL=${SB_METRICS_URL:-}"

  # The Outline server image to run.
  "${SB_IMAGE}"
)
"\${docker_command[@]}"
EOF
  chmod +x "${START_SCRIPT}"
  
  local STDERR_OUTPUT
  STDERR_OUTPUT="$({ "${START_SCRIPT}" >/dev/null; } 2>&1)" && return
  log_error "FAILED"
  log_error "${STDERR_OUTPUT}"
  return 1
}

function start_watchtower() {
  local -ir WATCHTOWER_REFRESH_SECONDS="${WATCHTOWER_REFRESH_SECONDS:-3600}"
  local -ar docker_watchtower_flags=(--name watchtower --log-driver local --restart always \
      -v /var/run/docker.sock:/var/run/docker.sock)

  # Check Docker daemon connectivity before running watchtower
  echo "Checking Docker daemon connectivity for Watchtower..."
  sleep 2
  docker info >/dev/null 2>&1 || { log_error "Docker daemon not accessible for Watchtower. Is it running on the host?"; return 1; }
  echo "Docker daemon reachable for Watchtower."

  local STDERR_OUTPUT
  STDERR_OUTPUT="$(docker run -d "${docker_watchtower_flags[@]}" containrrr/watchtower --cleanup --label-enable --tlsverify --interval "${WATCHTOWER_REFRESH_SECONDS}" 2>&1 >/dev/null)" && return
  log_error "FAILED"
  log_error "${STDERR_OUTPUT}"
  return 1
}

function fetch() {
  curl --silent --show-error --fail "$@"
}

function wait_shadowbox() {
  until fetch --insecure "${LOCAL_API_URL}/access-keys" >/dev/null; do sleep 1; done
}

function create_first_user() {
  fetch --insecure --request POST "${LOCAL_API_URL}/access-keys" >&2
}

function output_config() {
  echo "$@" >> "${ACCESS_CONFIG}"
}

function add_api_url_to_config() {
  output_config "apiUrl:${PUBLIC_API_URL}"
}

function get_field_value {
  grep "$1" "${ACCESS_CONFIG}" | sed "s/$1://"
}

function set_hostname() {
  local -ar urls=(
    'https://icanhazip.com/'
    'https://ipinfo.io/ip'
    'https://domains.google.com/checkip'
  )
  for url in "${urls[@]}"; do
    PUBLIC_HOSTNAME="$(fetch --ipv4 "${url}")" && return
  done
  echo "Failed to determine the server's IP address. Try using --hostname <server IP>." >&2
  return 1
}

function escape_json_string() {
  local input=$1
  for ((i = 0; i < ${#input}; i++)); do
    local char="${input:i:1}"
    local escaped="${char}"
    case "${char}" in
      $'"' ) escaped="\\\"";;
      $'\\') escaped="\\\\";;
      *)
        if [[ "${char}" < $'\x20' ]]; then
          case "${char}" in 
            $'\b') escaped="\\b";;
            $'\f') escaped="\\f";;
            $'\n') escaped="\\n";;
            $'\r') escaped="\\r";;
            $'\t') escaped="\\t";;
            *) escaped=$(printf "\u%04X" "'${char}")
          esac
        fi;;
    esac
    echo -n "${escaped}"
  done
}

# Main execution logic
function main() {
  # These files are used for detailed logging and last error capture.
  # Their creation and removal are handled by the 'finish' trap in the original script.
  # For a Docker entrypoint, these might not be strictly necessary, or
  # you might want to adjust their lifecycle.
  # For now, let's ensure they exist if needed by log_error
  FULL_LOG="$(mktemp -t outline_logXXXXXXXXXX)"
  LAST_ERROR="$(mktemp -t outline_last_errorXXXXXXXXXX)"
  export FULL_LOG LAST_ERROR # Export so sub-functions can use them

  # Re-implement a simplified 'finish' trap for debugging within the container
  trap 'local exit_code=$?; if (( exit_code != 0 )); then if [[ -s "${LAST_ERROR}" ]]; then log_error "\nLast error: $(< "${LAST_ERROR}")" >&2; fi; log_error "Full log: ${FULL_LOG}" >&2; fi; rm -f "${FULL_LOG}" "${LAST_ERROR}";' EXIT


  echo "Starting Outline server setup..."

  # Define environment variables with defaults
  export CONTAINER_NAME="${CONTAINER_NAME:-shadowbox}"
  export SHADOWBOX_DIR="${SHADOWBOX_DIR:-/opt/outline}"
  export ACCESS_CONFIG="${ACCESS_CONFIG:-${SHADOWBOX_DIR}/access.txt}"
  export SB_IMAGE="${SB_IMAGE:-quay.io/outline/shadowbox:stable}"
  
  # API port handling
  API_PORT="${FLAGS_API_PORT:-0}"
  if (( API_PORT == 0 )); then
    API_PORT=${SB_API_PORT:-$(get_random_port)}
  fi
  export API_PORT

  # Hostname handling
  PUBLIC_HOSTNAME="${FLAGS_HOSTNAME:-${SB_PUBLIC_IP:-}}"
  if [[ -z "${PUBLIC_HOSTNAME}" ]]; then
    run_step "Setting PUBLIC_HOSTNAME to external IP" set_hostname
  fi
  export PUBLIC_HOSTNAME

  # Clear access config if it exists
  if [[ -s "${ACCESS_CONFIG}" ]]; then
    cp "${ACCESS_CONFIG}" "${ACCESS_CONFIG}.bak" && true > "${ACCESS_CONFIG}"
  fi

  # Core setup steps
  run_step "Generating secret key" generate_secret_key
  run_step "Generating TLS certificate" generate_certificate
  run_step "Generating SHA-256 certificate fingerprint" generate_certificate_fingerprint
  run_step "Writing config" write_config
  
  # --- CRITICAL: Ensure Docker daemon is running on the HOST before this ---
  run_step "Starting Shadowbox" start_shadowbox
  run_step "Starting Watchtower" start_watchtower

  export PUBLIC_API_URL="https://${PUBLIC_HOSTNAME}:${API_PORT}/${SB_API_PREFIX}"
  export LOCAL_API_URL="https://localhost:${API_PORT}/${SB_API_PREFIX}"

  run_step "Waiting for Outline server to be healthy" wait_shadowbox
  run_step "Creating first user" create_first_user
  run_step "Adding API URL to config" add_api_url_to_config

  FIREWALL_STATUS="\
If you have connection problems, it may be that your router or cloud provider
blocks inbound connections, even though your machine seems to allow them.

Make sure to open the following ports on your firewall, router or cloud provider:
- Management port ${API_PORT}, for TCP
- Access key port (obtained from manager), for TCP and UDP
"

  cat <<END_OF_SERVER_OUTPUT

CONGRATULATIONS! Your Outline server is up and running.

To manage your Outline server, please copy the following line (including curly
brackets) into Step 2 of the Outline Manager interface:

{"apiUrl":"$(get_field_value apiUrl)","certSha256":"$(get_field_value certSha256)"}

${FIREWALL_STATUS}
END_OF_SERVER_OUTPUT

  # Keep the container running to allow access to the server
  tail -f /dev/null
}

main "$@"