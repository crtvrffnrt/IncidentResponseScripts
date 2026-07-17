#!/usr/bin/env bash
# WhoisFreaks Pivot - conservative WHOIS / Reverse-WHOIS investigation client.

set -Eeuo pipefail
IFS=$'\n\t'

readonly APP_NAME="whoisfreaks-pivot"
readonly APP_VERSION="1.1.1"
readonly SCHEMA_VERSION="1"
readonly DOC_VERIFIED="2026-07-17"
readonly API_BASE="https://api.whoisfreaks.com"
readonly REVERSE_ENDPOINT="${API_BASE}/v2.0/whois/reverse"
readonly LIVE_ENDPOINT="${API_BASE}/v2.0/whois/live"
readonly CREDITS_ENDPOINT="${API_BASE}/v1.0/whoisapi/usage"
readonly REVERSE_CREDITS_PER_PAGE=5
readonly LIVE_CREDITS_PER_QUERY=1
readonly DEFAULT_MAX_CREDITS=5
readonly DEFAULT_REVERSE_TTL=604800
readonly DEFAULT_LIVE_TTL=86400
readonly DEFAULT_KEY_FILE="/root/Tools/apikeys.txt"

CACHE_DIR="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/${APP_NAME}"
OUTPUT_DIR="."
KEY_FILE=""
NO_KEY_FILE=false
SHOW_KEY_SOURCE=false
DRY_RUN=false
ASSUME_YES=false
PAID_MODE=false
ALL_PAGES=false
REFRESH=false
CACHE_ENABLED=true
CACHE_TTL=""
ESTIMATE_ONLY=false
MAX_PAGES=1
PAGE=1
MAX_CREDITS=$DEFAULT_MAX_CREDITS
MODE="default"
EXACT=true
FORMAT="table"
OUTPUT_PATH=""
QUIET=false
VERBOSE=false
DEBUG=false
RETRIES=1
CONNECT_TIMEOUT=10
MAX_TIME=60
REDACT_QUERY=false
INTERACTIVE_APPROVED=false
COLOR_ENABLED=false
UI_INPUT=""
UI_FIELD=""
SEED_PIVOT_PROMPT=true
UI_RESET=""
UI_BOLD=""
UI_DIM=""
UI_CYAN=""
UI_BLUE=""
UI_GREEN=""
UI_YELLOW=""
UI_RED=""
API_KEY=""
KEY_SOURCE="none"
TMP_ROOT=""
HTTP_STATUS=""
HTTP_BODY=""
HTTP_HEADERS=""
CACHE_STATUS="miss"

die() { printf 'Error: %s\n' "$*" >&2; exit 2; }
warn() { printf 'Warning: %s\n' "$*" >&2; }
info() { $QUIET || printf '%s\n' "$*" >&2; }
verbose() { $VERBOSE && printf '%s\n' "$*" >&2 || true; }
debug() { $DEBUG && printf 'DEBUG: %s\n' "$(redact_text "$*")" >&2 || true; }

cleanup() {
  if [[ -n ${TMP_ROOT:-} && -d $TMP_ROOT ]]; then
    find "$TMP_ROOT" -type f -exec chmod u+w {} + 2>/dev/null || true
    rm -rf -- "$TMP_ROOT"
  fi
}
on_interrupt() { printf '\nInterrupted.\n' >&2; exit 130; }
trap cleanup EXIT
trap on_interrupt INT TERM

ensure_not_xtrace() {
  case $- in *x*) die "xtrace (set -x) is unsafe for credentialed requests; disable it first" ;; esac
}

make_tmp_root() {
  [[ -n $TMP_ROOT ]] && return 0
  TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/${APP_NAME}.XXXXXXXX")
  chmod 700 "$TMP_ROOT"
}

redact_text() {
  local text=${1-}
  if [[ -n ${API_KEY:-} ]]; then text=${text//"$API_KEY"/[REDACTED]}; fi
  text=$(printf '%s' "$text" | sed -E 's/([?&](apiKey|apikey|api_key)=)[^&[:space:]]+/\1[REDACTED]/Ig')
  printf '%s' "$text"
}

require_arg() { [[ $# -ge 2 && -n ${2:-} ]] || die "option $1 requires a value"; }
is_uint() { [[ ${1:-} =~ ^[0-9]+$ ]]; }
validate_range() {
  local label=$1 value=$2 min=$3 max=$4
  is_uint "$value" || die "$label must be an integer"
  (( value >= min && value <= max )) || die "$label must be between $min and $max"
}
reject_controls() {
  local value=${1-} label=${2:-value}
  [[ $value != *$'\n'* && $value != *$'\r'* ]] || die "$label must not contain newlines"
  LC_ALL=C grep -q '[[:cntrl:]]' <<<"$value" && die "$label contains control characters"
  return 0
}
validate_output_path() {
  local path=$1 parent
  reject_controls "$path" "output path"
  [[ -n $path && $path != -* ]] || die "invalid output path"
  parent=$(dirname -- "$path")
  [[ -d $parent ]] || die "output parent directory does not exist: $parent"
  [[ ! -L $path ]] || die "refusing to overwrite a symbolic link: $path"
}

normalize_domain() {
  local domain=${1,,}
  domain=${domain%.}
  reject_controls "$domain" domain
  [[ $domain != *://* && $domain != */* && $domain != *:* && $domain != *' '* ]] || die "expected a bare domain, not a URL, path, port, or whitespace"
  if command -v idn2 >/dev/null 2>&1 && [[ $domain == *[![:ascii:]]* ]]; then
    domain=$(idn2 --quiet --idna2008 "$domain") || die "invalid internationalized domain"
  fi
  (( ${#domain} <= 253 )) || die "domain is too long"
  [[ $domain =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "invalid domain: $domain"
  printf '%s' "$domain"
}

normalize_query_value() {
  local type=$1 value=$2
  reject_controls "$value" "query value"
  value=$(printf '%s' "$value" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')
  [[ -n $value ]] || die "query value is empty"
  (( ${#value} <= 320 )) || die "query value is too long"
  case $type in
    email)
      if $EXACT; then [[ $value =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die "invalid email address"; fi
      ;;
    keyword)
      (( ${#value} >= 3 && ${#value} <= 63 )) || die "keyword must contain 3 to 63 characters"
      ;;
    owner|company) ;;
    *) die "unsupported Reverse-WHOIS type '$type' (supported: email, owner, company, keyword)" ;;
  esac
  printf '%s' "$value"
}

urlencode() { jq -rn --arg v "$1" '$v|@uri'; }
sha256_text() {
  if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  else die "sha256sum or shasum is required for cache identifiers"
  fi
}

parse_key_file() {
  local file=$1 records count value
  [[ -r $file && -f $file ]] || die "WhoisFreaks key file is not a readable regular file: $file"
  records=$(awk '
    {
      line=$0
      sub(/^[[:space:]]*/, "", line)
      lower=tolower(line)
      if (lower ~ /^export[[:space:]]+/) sub(/^[^[:space:]]+[[:space:]]+/, "", line)
      lower=tolower(line)
      if (lower ~ /^(whoisfreaks_api_key|whoisfreaks)[[:space:]]*[=:]/) {
        sub(/^[^=:]+[=:][[:space:]]*/, "", line)
        sub(/^[[:space:]]*/, "", line); sub(/[[:space:]]*$/, "", line)
        quote=substr(line,1,1)
        if (quote=="\"" || quote=="'\''") {
          rest=substr(line,2); end=index(rest,quote)
          if (end==0) { print "INVALID\tunterminated quote"; next }
          value=substr(rest,1,end-1); tail=substr(rest,end+1)
          sub(/^[[:space:]]*/, "", tail)
          if (tail!="" && tail !~ /^#/) { print "INVALID\tunexpected text after quoted value"; next }
        } else {
          sub(/[[:space:]]+#.*/, "", line); sub(/[[:space:]]*$/, "", line); value=line
        }
        print "MATCH\t" value
      }
    }
  ' "$file")
  [[ $records != *$'INVALID\t'* ]] || die "malformed WhoisFreaks key assignment in $file"
  count=$(printf '%s\n' "$records" | awk -F '\t' '$1=="MATCH"{n++} END{print n+0}')
  (( count > 0 )) || die "no explicitly labelled WhoisFreaks or WHOISFREAKS_API_KEY entry found in $file"
  (( count == 1 )) || die "ambiguous multiple WhoisFreaks key entries in $file"
  value=$(printf '%s\n' "$records" | awk -F '\t' '$1=="MATCH"{sub(/^[^\t]*\t/,""); print; exit}')
  [[ -n $value ]] || die "empty WhoisFreaks key in $file"
  reject_controls "$value" "API key"
  printf '%s' "$value"
}

resolve_api_key() {
  ensure_not_xtrace
  if [[ -n ${WHOISFREAKS_API_KEY:-} ]]; then
    API_KEY=$WHOISFREAKS_API_KEY; KEY_SOURCE="environment:WHOISFREAKS_API_KEY"
  elif [[ -n ${WhoisFreaks:-} ]]; then
    API_KEY=$WhoisFreaks; KEY_SOURCE="environment:WhoisFreaks"
  elif [[ -n $KEY_FILE ]]; then
    API_KEY=$(parse_key_file "$KEY_FILE"); KEY_SOURCE="file:$KEY_FILE"
  elif ! $NO_KEY_FILE; then
    API_KEY=$(parse_key_file "$DEFAULT_KEY_FILE"); KEY_SOURCE="file:$DEFAULT_KEY_FILE"
  else
    die "no API key source enabled"
  fi
  [[ -n $API_KEY ]] || die "resolved API key is empty"
}

safe_key_source() {
  if [[ -n ${WHOISFREAKS_API_KEY:-} ]]; then printf 'environment:WHOISFREAKS_API_KEY'
  elif [[ -n ${WhoisFreaks:-} ]]; then printf 'environment:WhoisFreaks'
  elif [[ -n $KEY_FILE ]]; then printf 'file:%s' "$KEY_FILE"
  elif $NO_KEY_FILE; then printf 'disabled'
  else printf 'file:%s' "$DEFAULT_KEY_FILE"
  fi
}

estimate_credits() {
  local endpoint=$1 count=${2:-1}
  case $endpoint in reverse) printf '%d' $((REVERSE_CREDITS_PER_PAGE * count)) ;; live) printf '%d' $((LIVE_CREDITS_PER_QUERY * count)) ;; credits) printf 'unknown' ;; *) printf '0' ;; esac
}
enforce_budget() {
  local estimate=$1
  is_uint "$estimate" || die "credit cost is undocumented; use the explicit credits command only"
  (( estimate <= MAX_CREDITS )) || die "estimated cost ($estimate credits) exceeds --max-credits $MAX_CREDITS"
}
confirm_charge() {
  local description=$1 estimate=$2
  if $INTERACTIVE_APPROVED; then
    $DRY_RUN && return 1
    $ESTIMATE_ONLY && return 1
    return 0
  fi
  info "Intended operation: $description"
  info "Estimated maximum charge: $estimate credit(s). Prices can change; verified $DOC_VERIFIED."
  $DRY_RUN && { info "Dry run: no request sent."; return 1; }
  $ESTIMATE_ONLY && { info "Estimate only: no request sent."; return 1; }
  $ASSUME_YES && return 0
  [[ -t 0 ]] || die "confirmation required; use --yes for deliberate non-interactive execution"
  local reply
  read -r -p "Send this chargeable request? [y/N] " reply
  [[ $reply =~ ^[Yy]([Ee][Ss])?$ ]]
}

init_cache() {
  $CACHE_ENABLED || return 0
  mkdir -p -- "$CACHE_DIR"
  chmod 700 "$CACHE_DIR"
}
cache_id() { sha256_text "$1|$2"; }
cache_entry_valid() {
  local dir=$1 ttl=$2 now fetched
  [[ -f $dir/response.json && -f $dir/metadata.json && -f $dir/headers.json ]] || return 1
  jq -e . "$dir/response.json" >/dev/null 2>&1 || return 1
  jq -e --arg v "$SCHEMA_VERSION" '.parser_schema_version == $v and (.fetch_epoch|type)=="number"' "$dir/metadata.json" >/dev/null 2>&1 || return 1
  fetched=$(jq -r '.fetch_epoch' "$dir/metadata.json")
  now=$(date +%s)
  (( now - fetched <= ttl ))
}
cache_read() {
  local id=$1 ttl=$2 dir
  dir="$CACHE_DIR/$id"
  $CACHE_ENABLED || return 1
  $REFRESH && return 1
  if cache_entry_valid "$dir" "$ttl"; then
    HTTP_BODY="$dir/response.json"; HTTP_HEADERS="$dir/headers.json"; HTTP_STATUS=$(jq -r '.http_status' "$dir/metadata.json"); CACHE_STATUS="hit"; return 0
  fi
  return 1
}
cache_write() {
  local id=$1 endpoint_type=$2 metadata=$3 body=$4 headers=$5
  $CACHE_ENABLED || return 0
  local dir="$CACHE_DIR/$id" stage lock_fd=""
  init_cache
  make_tmp_root
  stage=$(mktemp -d "$CACHE_DIR/.stage.${id}.XXXXXXXX")
  chmod 700 "$stage"
  if command -v flock >/dev/null 2>&1; then exec {lock_fd}>"$CACHE_DIR/.lock"; flock "$lock_fd"; fi
  cp -- "$body" "$stage/response.json"
  jq -n --argjson h "$(safe_headers_json "$headers")" '$h' >"$stage/headers.json"
  jq -n --arg id "$id" --arg endpoint "$endpoint_type" --argjson request "$metadata" --arg version "$SCHEMA_VERSION" --arg status "$HTTP_STATUS" --arg fetched "$(date -u +%FT%TZ)" --argjson epoch "$(date +%s)" \
    '{cache_id:$id,endpoint_type:$endpoint,request:$request,parser_schema_version:$version,http_status:$status,fetch_timestamp:$fetched,fetch_epoch:$epoch}' >"$stage/metadata.json"
  chmod 600 "$stage"/*
  [[ -d $dir ]] && rm -rf -- "$dir"
  mv -- "$stage" "$dir"
  [[ -n $lock_fd ]] && { flock -u "$lock_fd"; exec {lock_fd}>&-; }
}

safe_headers_json() {
  local file=$1
  awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*(content-type|x-ratelimit-allowed-requests|x-ratelimit-remaining-requests|x-ratelimit-remaining-time):/ {gsub(/\r/,""); name=$1; sub(/:$/,"",name); $1=""; sub(/^ /,""); print tolower(name) "\t" $0}' "$file" | jq -Rn '[inputs|split("\t")|{(.[0]):.[1]}]|add // {}'
}
rate_limit_summary() {
  local file=$1 allowed remaining ns seconds
  allowed=$(awk 'BEGIN{IGNORECASE=1} /^x-ratelimit-allowed-requests:/ {gsub(/\r/,""); print $2}' "$file" | tail -1)
  remaining=$(awk 'BEGIN{IGNORECASE=1} /^x-ratelimit-remaining-requests:/ {gsub(/\r/,""); print $2}' "$file" | tail -1)
  ns=$(awk 'BEGIN{IGNORECASE=1} /^x-ratelimit-remaining-time:/ {gsub(/\r/,""); print $2}' "$file" | tail -1)
  if is_uint "$ns"; then seconds=$(( (ns + 999999999) / 1000000000 )); else seconds="unknown"; fi
  [[ -n $allowed || -n $remaining || -n $ns ]] && verbose "Rate limit: allowed=${allowed:-?}, remaining=${remaining:-?}, reset=${seconds}s"
}
rate_limit_wait_seconds() {
  local file=$1 ns
  ns=$(awk 'BEGIN{IGNORECASE=1} /^x-ratelimit-remaining-time:/ {gsub(/\r/,""); print $2}' "$file" | tail -1)
  is_uint "$ns" || return 1
  printf '%d' $(( (ns + 999999999) / 1000000000 + 1 ))
}

# Test-only HTTP adapter. A fixture consists of NAME.json, optionally NAME.headers and NAME.status.
fixture_http() {
  local fixture=${WHOISFREAKS_TEST_FIXTURE:-} dir=${WHOISFREAKS_TEST_FIXTURE_DIR:-}
  [[ -n $fixture && -n $dir ]] || die "test fixture adapter requires WHOISFREAKS_TEST_FIXTURE and WHOISFREAKS_TEST_FIXTURE_DIR"
  [[ -f $dir/$fixture.json ]] || die "missing HTTP fixture: $fixture.json"
  make_tmp_root
  HTTP_BODY=$(mktemp "$TMP_ROOT/body.XXXXXXXX")
  HTTP_HEADERS=$(mktemp "$TMP_ROOT/headers.XXXXXXXX")
  cp -- "$dir/$fixture.json" "$HTTP_BODY"
  [[ -f $dir/$fixture.headers ]] && cp -- "$dir/$fixture.headers" "$HTTP_HEADERS" || : >"$HTTP_HEADERS"
  HTTP_STATUS=$(if [[ -f $dir/$fixture.status ]]; then tr -d '[:space:]' <"$dir/$fixture.status"; else printf '200'; fi)
  [[ -n ${WHOISFREAKS_TEST_NETWORK_GUARD_FILE:-} ]] && printf 'fixture\n' >>"$WHOISFREAKS_TEST_NETWORK_GUARD_FILE"
}

curl_http() {
  local endpoint=$1 params_json=$2 attempt=0 wait_s rc cfg body headers status jitter
  ensure_not_xtrace
  resolve_api_key
  make_tmp_root
  while :; do
    cfg=$(mktemp "$TMP_ROOT/curl.XXXXXXXX"); body=$(mktemp "$TMP_ROOT/body.XXXXXXXX"); headers=$(mktemp "$TMP_ROOT/headers.XXXXXXXX")
    chmod 600 "$cfg" "$body" "$headers"
    {
      printf 'silent\nshow-error\nlocation\nrequest = "GET"\n'
      printf 'connect-timeout = %q\nmax-time = %q\n' "$CONNECT_TIMEOUT" "$MAX_TIME"
      printf 'dump-header = %q\noutput = %q\nwrite-out = "%%{http_code}"\n' "$headers" "$body"
      printf 'url = "%s?apiKey=%s' "$endpoint" "$(urlencode "$API_KEY")"
      jq -r 'to_entries[]|"&\(.key|@uri)=\(.value|tostring|@uri)"' <<<"$params_json" | tr -d '\n'
      printf '"\n'
    } >"$cfg"
    set +e
    status=$(curl --config "$cfg" 2>"$TMP_ROOT/curl.err")
    rc=$?
    set -e
    : >"$cfg"
    if (( rc != 0 )); then
      case $rc in 6) warn "DNS resolution failed" ;; 28) warn "request timed out" ;; 35|51|58|60|66|77|80|82|83|90|91) warn "TLS validation or handshake failed" ;; *) warn "HTTP transport failed (curl exit $rc)" ;; esac
      if (( attempt < RETRIES )); then jitter=$((RANDOM % 2)); sleep $((2 ** attempt + jitter)); ((attempt+=1)); continue; fi
      debug "curl error: $(<"$TMP_ROOT/curl.err")"
      return 1
    fi
    HTTP_STATUS=$status; HTTP_BODY=$body; HTTP_HEADERS=$headers
    rate_limit_summary "$headers"
    if [[ $status == 429 ]] && (( attempt < RETRIES )); then
      wait_s=$(rate_limit_wait_seconds "$headers" || printf '2')
      (( wait_s <= 65 )) || wait_s=65
      info "Rate limited; retrying once after ${wait_s}s."
      sleep "$wait_s"; ((attempt+=1)); continue
    fi
    if { [[ $status == 408 ]] || [[ $status =~ ^5[0-9][0-9]$ ]]; } && (( attempt < RETRIES )); then jitter=$((RANDOM % 2)); sleep $((2 ** attempt + jitter)); ((attempt+=1)); continue; fi
    return 0
  done
}

http_request() {
  local endpoint=$1 params=$2
  CACHE_STATUS="miss"
  if [[ -n ${WHOISFREAKS_TEST_FIXTURE_DIR:-} ]]; then fixture_http
  else curl_http "$endpoint" "$params"
  fi
}

handle_http_status() {
  local status=$HTTP_STATUS message=""
  jq -e . "$HTTP_BODY" >/dev/null 2>&1 || die "API returned malformed JSON (HTTP $status)"
  message=$(jq -r 'if type=="object" then (.message // .error // empty) else empty end' "$HTTP_BODY" 2>/dev/null || true)
  message=$(redact_text "$message")
  case $status in
    200) return 0 ;;
    206) warn "API returned a documented partial response (206): ${message:-some records may be unavailable}"; return 0 ;;
    210) warn "API returned a documented cached fallback (210) because the upstream WHOIS server failed"; return 0 ;;
    400) die "invalid API request (400): ${message:-check parameters}" ;;
    401) die "API key invalid or unavailable (401)" ;;
    403) die "request forbidden (403)" ;;
    404) die "API endpoint or record not found (404)" ;;
    405) die "invalid HTTP method rejected by API (405)" ;;
    408) die "WhoisFreaks could not complete the request in time (408); retry budget exhausted" ;;
    412) die "API plan request limit exceeded or subscription canceled (412)" ;;
    413) die "API credit allowance exceeded (413)" ;;
    429) die "rate limit exceeded (429); retry budget exhausted" ;;
    5??) die "WhoisFreaks service error ($status): ${message:-transient server failure}" ;;
    *) die "unexpected HTTP status $status: ${message:-no details}" ;;
  esac
}

normalize_response() {
  local raw=$1 query_type=$2 query_value=$3 source_page=$4 cache_status=$5 fetch_time=${6:-$(date -u +%FT%TZ)}
  jq --arg qt "$query_type" --arg qv "$query_value" --argjson page "$source_page" --arg cs "$cache_status" --arg ft "$fetch_time" '
    def arr: if .==null then [] elif type=="array" then . else [.] end;
    def contact($x): ($x // {}) | {id:(.id//null),name:(.name//null),company:(.company//.organization//null),street:(.street//null),city:(.city//null),state:(.state//null),postal_code:(.zip_code//.postal_code//null),country:(.country_name//.country_code//null),country_code:(.country_code//null),email:(.email_address//.email//null),phone:(.phone//.phone_number//null)};
    def rec($historical): . as $r | {
      domain:($r.domain_name//null), record_type:(if $historical then "historical" else "current" end), historical:$historical,
      query_time:($r.query_time//null), creation_date:($r.create_date//null), update_date:($r.update_date//null), expiry_date:($r.expiry_date//null),
      registrar:{name:($r.domain_registrar.registrar_name//null),iana_id:($r.domain_registrar.iana_id//null),whois_server:($r.domain_registrar.whois_server//$r.whois_server//null),website:($r.domain_registrar.website_url//null),email:($r.domain_registrar.email_address//null),phone:($r.domain_registrar.phone_number//null)},
      registrant:contact($r.registrant_contact), administrative:contact($r.administrative_contact), technical:contact($r.technical_contact), billing:contact($r.billing_contact),
      nameservers:(($r.name_servers//[])|arr), statuses:(($r.domain_status//[])|arr), registry_data:($r.registry_data//{}), privacy_redacted:(([contact($r.registrant_contact).name,contact($r.registrant_contact).company,contact($r.registrant_contact).email]|map(select(.!=null)|ascii_downcase)|join(" "))|test("redact|privacy|withheld|proxy")),
      source:{page:$page,query_type:$qt,query_value:$qv,cache_status:$cs,fetch_timestamp:$ft}
    };
    (if type=="array" then .[0] else . end) as $root |
    ($root.whois_domains_historical // (if ($root.domain_name? != null) then [$root] else [] end)) as $records |
    {schema_version:"1",metadata:{source:"WhoisFreaks",query_type:$qt,query_value:$qv,source_page:$page,cache_status:$cs,fetch_timestamp:$ft,http_total_results:($root.total_Result//($records|length)),total_pages:($root.total_Pages//1),current_page:($root.current_Page//$page)},results:[$records[]|rec($root.whois_domains_historical!=null)]}
  ' "$raw"
}

domains_unique() { jq -r '.results[].domain // empty' "$1" | awk '{k=tolower($0); if(!seen[k]++) print}' ; }
csv_output() {
  jq -r '["domain","record_type","creation_date","update_date","expiry_date","registrar","registrant","organization","matched_field","source_page"],(.results[]|[.domain,.record_type,.creation_date,.update_date,.expiry_date,.registrar.name,.registrant.name,.registrant.company,(.matched_field//""),.source.page])|@csv' "$1"
}
table_output() {
  local file=$1
  { printf 'DOMAIN\tCREATED\tEXPIRES\tREGISTRAR\tREGISTRANT / ORGANIZATION\tMATCH\tPAGE\n'; jq -r '.results[]|[.domain//"-",.creation_date//"-",.expiry_date//"-",.registrar.name//"-",(.registrant.company//.registrant.name//"-"),(.matched_field//"-"),(.source.page|tostring)]|@tsv' "$file"; } |
    if command -v column >/dev/null 2>&1; then column -t -s $'\t'; else sed 's/\t/  /g'; fi
}
html_output() {
  local file=$1
  jq -r '
    def h: tostring|@html;
    "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>WhoisFreaks investigation</title><style>body{font:14px system-ui;margin:2rem;color:#18212b}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd3da;padding:.45rem;text-align:left;vertical-align:top}th{background:#edf2f6;position:sticky;top:0}.warn{background:#fff4ce;padding:1rem}code{word-break:break-all}</style></head><body><h1>WHOIS investigation report</h1><p><b>Query:</b> "+(.metadata.query_type|h)+" = <code>"+(.metadata.query_value|h)+"</code> | page "+(.metadata.source_page|h)+" | cache: "+(.metadata.cache_status|h)+"</p><p class=\"warn\">WHOIS data may be stale or historical. Privacy services can produce false correlations. Matches are investigative leads, not ownership proof.</p><table><thead><tr><th>Domain</th><th>Record</th><th>Created</th><th>Expires</th><th>Registrar</th><th>Registrant / organization</th><th>Matched field</th><th>Page</th></tr></thead><tbody>"+
    ([.results[]|"<tr><td>"+(.domain|h)+"</td><td>"+(.record_type|h)+(if .privacy_redacted then " (privacy-redacted)" else "" end)+"</td><td>"+(.creation_date//""|h)+"</td><td>"+(.expiry_date//""|h)+"</td><td>"+(.registrar.name//""|h)+"</td><td>"+(.registrant.company//.registrant.name//""|h)+"</td><td>"+(.matched_field//""|h)+"</td><td>"+(.source.page|h)+"</td></tr>"]|join(""))+"</tbody></table></body></html>"
  ' "$file"
}
emit_output() {
  local normalized=$1 raw=${2:-$1} destination=${OUTPUT_PATH:-}
  if [[ -z $destination && -n $OUTPUT_DIR && $OUTPUT_DIR != . ]]; then
    [[ -d $OUTPUT_DIR ]] || die "output directory does not exist: $OUTPUT_DIR"
    destination="$OUTPUT_DIR/${APP_NAME}-$(date -u +%Y%m%dT%H%M%SZ).${FORMAT}"
  fi
  if [[ -n $destination ]]; then validate_output_path "$destination"; umask 077; fi
  case $FORMAT in
    table) [[ -n $destination ]] && table_output "$normalized" >"$destination" || table_output "$normalized" ;;
    domains) [[ -n $destination ]] && domains_unique "$normalized" >"$destination" || domains_unique "$normalized" ;;
    json) [[ -n $destination ]] && jq . "$normalized" >"$destination" || jq . "$normalized" ;;
    csv) [[ -n $destination ]] && csv_output "$normalized" >"$destination" || csv_output "$normalized" ;;
    html) [[ -n $destination ]] && html_output "$normalized" >"$destination" || html_output "$normalized" ;;
    raw) [[ -n $destination ]] && jq . "$raw" >"$destination" || jq . "$raw" ;;
    *) die "unsupported format: $FORMAT" ;;
  esac
  [[ -n $destination ]] && { chmod 600 "$destination"; info "Wrote $destination"; }
  return 0
}

reverse_command() {
  local type="" value="" pages_requested normalized aggregate page_n estimate params metadata cache_key ttl total_pages current_page next
  while (($#)); do
    case $1 in
      --type) require_arg "$@"; type=$2; shift 2 ;; --value) require_arg "$@"; value=$2; shift 2 ;;
      --help|-h) reverse_help; return ;; *) parse_common "$@"; shift "$PARSE_SHIFT" ;; esac
  done
  [[ -n $type && -n $value ]] || die "reverse requires --type and --value"
  value=$(normalize_query_value "$type" "$value")
  $SHOW_KEY_SOURCE && info "API key source: $(safe_key_source)"
  validate_range --page "$PAGE" 1 1000000; validate_range --max-pages "$MAX_PAGES" 1 1000; validate_range --max-credits "$MAX_CREDITS" 0 1000000
  pages_requested=$MAX_PAGES
  $ALL_PAGES && pages_requested=$MAX_PAGES
  (( pages_requested > 1 )) && ! $PAID_MODE && die "more than one page requires --paid-mode"
  $ALL_PAGES && ! $PAID_MODE && die "--all-pages requires --paid-mode"
  estimate=$(estimate_credits reverse "$pages_requested"); enforce_budget "$estimate"
  confirm_charge "Reverse WHOIS $type='$value', exact=$EXACT, mode=$MODE, starting page=$PAGE, at most $pages_requested page(s)" "$estimate" || return 0
  aggregate=""; total_pages=0
  for ((page_n=PAGE; page_n<PAGE+pages_requested; page_n++)); do
    params=$(jq -n --arg type "$type" --arg value "$value" --arg mode "$MODE" --arg exact "$EXACT" --argjson page "$page_n" '{mode:$mode,exact:$exact,page:$page,format:"json"}+{($type):$value}')
    metadata=$(jq -n --arg type "$type" --arg value "$value" --arg mode "$MODE" --arg exact "$EXACT" --argjson page "$page_n" '{type:$type,value:$value,mode:$mode,exact:$exact,page:$page,format:"json"}')
    cache_key=$(cache_id reverse "$(jq -cS . <<<"$metadata")"); ttl=${CACHE_TTL:-$DEFAULT_REVERSE_TTL}
    if cache_read "$cache_key" "$ttl"; then
      verbose "Cache hit: $cache_key"
      handle_http_status
    else
      http_request "$REVERSE_ENDPOINT" "$params" || die "request failed"
      handle_http_status
      cache_write "$cache_key" reverse "$metadata" "$HTTP_BODY" "$HTTP_HEADERS"
    fi
    make_tmp_root; normalized=$(mktemp "$TMP_ROOT/normalized.XXXXXXXX.json")
    normalize_response "$HTTP_BODY" "$type" "$($REDACT_QUERY && printf '[REDACTED]' || printf '%s' "$value")" "$page_n" "$CACHE_STATUS" >"$normalized"
    current_page=$(jq -r '.metadata.current_page' "$normalized"); total_pages=$(jq -r '.metadata.total_pages' "$normalized")
    if [[ -z $aggregate ]]; then aggregate=$normalized
    else
      next=$(mktemp "$TMP_ROOT/aggregate.XXXXXXXX.json")
      jq -s '.[0] as $a|.[1] as $b|$a|.results += $b.results|.metadata.pages_fetched=((.metadata.pages_fetched//[.metadata.current_page])+[$b.metadata.current_page]|unique)|.metadata.current_page=$b.metadata.current_page|.metadata.total_pages=$b.metadata.total_pages' "$aggregate" "$normalized" >"$next"; aggregate=$next
    fi
    (( current_page >= total_pages )) && break
    $ALL_PAGES || (( page_n + 1 < PAGE + pages_requested )) || break
  done
  if [[ $(jq '.results|length' "$aggregate") -eq 0 ]]; then info "No records found."; fi
  emit_output "$aggregate" "$HTTP_BODY"
  total_pages=$(jq -r '.metadata.total_pages' "$aggregate"); current_page=$(jq -r '.metadata.current_page' "$aggregate")
  if (( total_pages > current_page )); then
    info "$((total_pages-current_page)) additional page(s) appear available; they were not fetched automatically."
    printf 'Next page: %q reverse --type %q --value %q --page %d --max-pages 1\n' "$0" "$type" "$value" "$((current_page+1))" >&2
  fi
  return 0
}

parse_whois_text() {
  local input=$1
  awk -F: '
    function trim(s){gsub(/^[ \t]+|[ \t]+$/, "", s); return s}
    function emit(role,field,label,value,remote,mapping){gsub(/\t/," ",value); if(value!="") print role "\t" field "\t" label "\t" value "\t" remote "\t" mapping}
    /^[[:space:]]*[%#;]/ || !/:/ {next}
    {
      label=tolower(trim($1)); value=$0; sub(/^[^:]*:[ \t]*/,"",value); value=trim(value)
      if(label=="registrant email") emit("registrant","email",$1,value,"email","exact")
      else if(label=="admin email"||label=="administrative contact email"||label=="administrative email") emit("administrative","email",$1,value,"email","exact")
      else if(label=="tech email"||label=="technical contact email"||label=="technical email") emit("technical","email",$1,value,"email","exact")
      else if(label=="billing email") emit("billing","email",$1,value,"email","exact")
      else if(label=="registrant name"||label=="registrant") emit("registrant","name",$1,value,"owner","exact")
      else if(label=="registrant organization"||label=="registrant organisation"||label=="registrant org") emit("registrant","organization",$1,value,"company","exact")
      else if(label=="registrant street") emit("registrant","street",$1,value,"", "local-only")
      else if(label=="registrant city") emit("registrant","city",$1,value,"", "local-only")
      else if(label=="registrant state/province"||label=="registrant state") emit("registrant","state",$1,value,"", "local-only")
      else if(label=="registrant postal code"||label=="registrant zip code") emit("registrant","postal_code",$1,value,"", "local-only")
      else if(label=="registrant country") emit("registrant","country",$1,value,"", "local-only")
      else if(label=="registrant phone") emit("registrant","phone",$1,value,"", "local-only")
      else if(label=="admin phone"||label=="administrative contact phone"||label=="administrative phone") emit("administrative","phone",$1,value,"", "local-only")
      else if(label=="tech phone"||label=="technical contact phone"||label=="technical phone") emit("technical","phone",$1,value,"", "local-only")
      else if(label=="billing phone") emit("billing","phone",$1,value,"", "local-only")
      else if(label=="registrar"||label=="registrar name") emit("registrar","name",$1,value,"", "local-only")
      else if(label=="registrar iana id") emit("registrar","iana_id",$1,value,"", "local-only")
      else if(label=="registry domain id") emit("registry","domain_id",$1,value,"", "local-only")
      else if(label=="registrar whois server") emit("registrar","whois_server",$1,value,"", "local-only")
      else if(label=="registrar abuse contact email") emit("registrar","abuse_email",$1,value,"email", "approximate")
      else if(label=="registrar abuse contact phone") emit("registrar","abuse_phone",$1,value,"", "local-only")
      else if(label=="name server"||label=="nserver") emit("infrastructure","nameserver",$1,value,"", "local-only")
      else if(label=="domain status"||label=="status") emit("registry","status",$1,value,"", "local-only")
      else if(label=="dnssec") emit("infrastructure","dnssec",$1,value,"", "local-only")
      else if(label=="creation date"||label=="created date"||label=="created") emit("registry","creation_date",$1,value,"", "local-only")
      else if(label=="updated date"||label=="last updated") emit("registry","update_date",$1,value,"", "local-only")
      else if(label=="expiry date"||label=="expiration date"||label=="registry expiry date") emit("registry","expiry_date",$1,value,"", "local-only")
      else if(label=="domain name") emit("registry","domain",$1,value,"keyword", "approximate")
    }
  ' "$input" | jq -Rn '[inputs|split("\t")|{role:.[0],field:.[1],label:.[2],value:.[3],remote_type:(if .[4]=="" then null else .[4] end),mapping:.[5]}]|unique_by([.role,.field,(.value|ascii_downcase)])|{schema_version:"1",fields:.,pivots:[.[]|select(.remote_type!=null)]}'
}

parse_whois_command() {
  local source=${1:--} temp
  [[ $# -le 1 ]] || die "parse-whois accepts one file or '-'"
  if [[ $source == - ]]; then make_tmp_root; temp=$(mktemp "$TMP_ROOT/whois.XXXXXXXX"); sed 's/\r$//' >"$temp"; source=$temp
  else [[ -r $source && -f $source ]] || die "WHOIS input is not a readable regular file: $source"; fi
  parse_whois_text "$source" | jq .
}

seed_command() {
  local domain="" source="local" whois_file="" raw parsed estimate params metadata cache_key ttl normalized choice
  [[ $# -gt 0 && $1 != -* ]] && { domain=$1; shift; }
  while (($#)); do
    case $1 in
      --seed-source) require_arg "$@"; source=$2; shift 2 ;; --whois-file) require_arg "$@"; whois_file=$2; source=file; shift 2 ;;
      --help|-h) seed_help; return ;; *) parse_common "$@"; shift "$PARSE_SHIFT" ;; esac
  done
  [[ -n $domain ]] || die "seed requires a domain"
  domain=$(normalize_domain "$domain")
  make_tmp_root; raw=$(mktemp "$TMP_ROOT/whois.XXXXXXXX")
  case $source in
    local) command -v whois >/dev/null 2>&1 || die "optional whois command is unavailable; use --seed-source file with --whois-file"; info "Running local whois for $domain (no WhoisFreaks credits)."; whois -- "$domain" >"$raw" ;;
    file) [[ -r $whois_file && -f $whois_file ]] || die "--whois-file is required and must be readable"; sed 's/\r$//' "$whois_file" >"$raw" ;;
    stdin) sed 's/\r$//' >"$raw" ;;
    api)
      $SHOW_KEY_SOURCE && info "API key source: $(safe_key_source)"
      estimate=$(estimate_credits live 1); enforce_budget "$estimate"
      confirm_charge "Live WHOIS for $domain" "$estimate" || return 0
      params=$(jq -n --arg domain "$domain" '{domainName:$domain,format:"json"}')
      metadata=$(jq -n --arg domain "$domain" '{domainName:$domain,format:"json"}')
      cache_key=$(cache_id live "$(jq -cS . <<<"$metadata")"); ttl=${CACHE_TTL:-$DEFAULT_LIVE_TTL}
      if cache_read "$cache_key" "$ttl"; then handle_http_status; else http_request "$LIVE_ENDPOINT" "$params" || die "request failed"; handle_http_status; cache_write "$cache_key" live "$metadata" "$HTTP_BODY" "$HTTP_HEADERS"; fi
      normalized=$(mktemp "$TMP_ROOT/live.XXXXXXXX.json"); normalize_response "$HTTP_BODY" domain "$domain" 1 "$CACHE_STATUS" >"$normalized"
      jq -r '(.results[0] // {}) | ["Domain Name: "+(.domain//""),"Creation Date: "+(.creation_date//""),"Updated Date: "+(.update_date//""),"Expiry Date: "+(.expiry_date//""),"Registrar: "+(.registrar.name//""),"Registrar IANA ID: "+(.registrar.iana_id//""),"Registrant Name: "+(.registrant.name//""),"Registrant Organization: "+(.registrant.company//""),"Registrant Email: "+(.registrant.email//""),"Registrant Phone: "+(.registrant.phone//""),(.nameservers[]?|"Name Server: "+.)]|.[]' "$normalized" >"$raw"
      ;;
    *) die "unsupported seed source '$source' (local, file, stdin, api)" ;;
  esac
  parsed=$(mktemp "$TMP_ROOT/pivots.XXXXXXXX.json"); parse_whois_text "$raw" >"$parsed"
  jq -r '.fields|to_entries[]|"\(.key+1). [\(.value.role)] \(.value.field): \(.value.value) — \(.value.mapping)\(if .value.remote_type then " -> remote "+.value.remote_type else " -> local correlation / lead export" end)"' "$parsed"
  info "No pivot was executed automatically. API-supported dimensions are email, owner, company, and keyword only."
  if $SEED_PIVOT_PROMPT && [[ -t 0 && $(jq '.pivots|length' "$parsed") -gt 0 ]]; then
    read -r -p "Select one numbered API-supported pivot to print its command, or Enter to stop: " choice
    if [[ $choice =~ ^[0-9]+$ ]]; then
      jq -r --argjson n "$choice" --arg script "$0" '.fields[$n-1]|select(.remote_type!=null)|"Suggested (not executed): \($script|@sh) reverse --type \(.remote_type|@sh) --value \(.value|@sh)"' "$parsed"
    fi
  fi
}

filter_command() {
  local file="" field="" value="" local_exact=false from="" to="" normalized temp jq_filter
  [[ $# -gt 0 && $1 != -* ]] && { file=$1; shift; }
  while (($#)); do
    case $1 in --field) require_arg "$@"; field=$2; shift 2 ;; --value) require_arg "$@"; value=$2; shift 2 ;; --exact) local_exact=true; shift ;; --substring) local_exact=false; shift ;; --from) require_arg "$@"; from=$2; shift 2 ;; --to) require_arg "$@"; to=$2; shift 2 ;; --help|-h) filter_help; return ;; *) parse_common "$@"; shift "$PARSE_SHIFT" ;; esac
  done
  [[ -r $file && -f $file ]] || die "filter requires a readable JSON file"
  jq -e . "$file" >/dev/null 2>&1 || die "filter input is not valid JSON"
  make_tmp_root; normalized=$(mktemp "$TMP_ROOT/filter-input.XXXXXXXX.json")
  if jq -e '.schema_version and .results' "$file" >/dev/null 2>&1; then cp -- "$file" "$normalized"; else normalize_response "$file" local "local filter" 0 local >"$normalized"; fi
  [[ -n $field ]] || die "filter requires --field"
  reject_controls "$value" "filter value"
  jq_filter='
    def vals($f):
      if $f=="any_email" then [.registrant.email,.administrative.email,.technical.email,.billing.email,.registrar.email]
      elif $f=="registrant_email" then [.registrant.email] elif $f=="admin_email" then [.administrative.email] elif $f=="tech_email" then [.technical.email] elif $f=="billing_email" then [.billing.email]
      elif $f=="any_contact_name" then [.registrant.name,.administrative.name,.technical.name,.billing.name]
      elif $f=="organization" or $f=="company" then [.registrant.company,.administrative.company,.technical.company,.billing.company]
      elif $f=="phone" then [.registrant.phone,.administrative.phone,.technical.phone,.billing.phone,.registrar.phone]
      elif $f=="street" then [.registrant.street,.administrative.street,.technical.street,.billing.street]
      elif $f=="city" then [.registrant.city,.administrative.city,.technical.city,.billing.city]
      elif $f=="postal_code" then [.registrant.postal_code,.administrative.postal_code,.technical.postal_code,.billing.postal_code]
      elif $f=="country" then [.registrant.country,.registrant.country_code,.administrative.country,.technical.country,.billing.country]
      elif $f=="registrar" then [.registrar.name] elif $f=="iana_id" then [.registrar.iana_id]
      elif $f=="registry_domain_id" then [.registry_data.domain_handle,.registry_data.domain_id]
      elif $f=="nameserver" then .nameservers elif $f=="status" then .statuses
      elif $f=="creation_date" then [.creation_date] elif $f=="update_date" then [.update_date] elif $f=="expiry_date" then [.expiry_date]
      else error("unsupported filter field: "+$f) end | map(select(.!=null)|tostring);
    .results |= [.[] as $r | ($r|vals($field)) as $vs | (if ($field|test("_date$")) and (($from|length)>0 or ($to|length)>0) then [$vs[]|select(($from=="" or . >= $from) and ($to=="" or . <= $to))] else [$vs[]|select(if $exact then ascii_downcase==($value|ascii_downcase) else ascii_downcase|contains($value|ascii_downcase) end)] end) as $m | select(($m|length)>0) | $r + {matched_field:($field+": "+($m|join("; "))),local_match:true}] | .metadata.query_type="local-filter" | .metadata.query_value=($field+"="+$value)'
  temp=$(mktemp "$TMP_ROOT/filtered.XXXXXXXX.json")
  jq --arg field "$field" --arg value "$value" --arg from "$from" --arg to "$to" --argjson exact "$local_exact" "$jq_filter" "$normalized" >"$temp" || die "unsupported or invalid local filter"
  info "Local-only correlation: no API request was made."
  emit_output "$temp" "$file"
}

cache_command() {
  local action=${1:-stats} key=""
  (($#)) && shift
  if [[ $action == show ]]; then key=${1:-}; (($#)) && shift; fi
  while (($#)); do parse_common "$@"; shift "$PARSE_SHIFT"; done
  init_cache
  case $action in
    list) find "$CACHE_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort ;;
    stats)
      local count bytes; count=$(find "$CACHE_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l); bytes=$(du -sb "$CACHE_DIR" 2>/dev/null | awk '{print $1}'); printf 'Cache: %s\nEntries: %s\nBytes: %s\n' "$CACHE_DIR" "$count" "${bytes:-0}" ;;
    show) [[ $key =~ ^[a-f0-9]{64}$ ]] || die "cache key must be a 64-character SHA-256 identifier"; [[ -f $CACHE_DIR/$key/metadata.json ]] || die "cache entry not found"; jq '{cache_id,endpoint_type,request:(.request|if has("value") then .value="[REDACTED]" else . end),parser_schema_version,http_status,fetch_timestamp}' "$CACHE_DIR/$key/metadata.json" ;;
    purge)
      [[ -t 0 || $ASSUME_YES == true ]] || die "cache purge requires an interactive terminal or --yes"
      if ! $ASSUME_YES; then local reply; read -r -p "Purge all cache entries under $CACHE_DIR? [y/N] " reply; [[ $reply =~ ^[Yy] ]] || return 0; fi
      find "$CACHE_DIR" -mindepth 1 -maxdepth 1 -type d -name '[a-f0-9]*' -exec rm -rf -- {} +
      info "Cache purged."
      ;;
    *) die "cache action must be list, stats, show KEY, or purge" ;;
  esac
}

credits_command() {
  local live=false
  while (($#)); do case $1 in --live) live=true; shift ;; --help|-h) credits_help; return ;; *) parse_common "$@"; shift "$PARSE_SHIFT" ;; esac; done
  printf 'Documented estimates (verified %s):\n  Reverse WHOIS: %d credits/page (default 50 records; mini 100 records)\n  Live WHOIS: %d credit/successful domain query\n' "$DOC_VERIFIED" "$REVERSE_CREDITS_PER_PAGE" "$LIVE_CREDITS_PER_QUERY"
  if $live; then
    $SHOW_KEY_SOURCE && info "API key source: $(safe_key_source)"
    $PAID_MODE || die "live credit-ledger lookup requires --paid-mode because its own credit cost is undocumented"
    confirm_charge "Credit Usage API lookup (endpoint cost is not documented)" "unknown" || return 0
    http_request "$CREDITS_ENDPOINT" '{}' || die "credit usage request failed"; handle_http_status; jq . "$HTTP_BODY"
  else
    info "Credit Usage API was not called. Its own credit cost is not stated in the official credit ledger."
  fi
}

config_command() {
  jq -n --arg version "$APP_VERSION" --arg reverse "$REVERSE_ENDPOINT" --arg live "$LIVE_ENDPOINT" --arg credits "$CREDITS_ENDPOINT" --arg key_source "$(safe_key_source)" --arg cache "$CACHE_DIR" --arg mode "$MODE" --arg exact "$EXACT" --argjson max_pages "$MAX_PAGES" --argjson max_credits "$MAX_CREDITS" --arg cache_enabled "$CACHE_ENABLED" '{version:$version,endpoints:{reverse:$reverse,live:$live,credit_usage:$credits},key_source:$key_source,cache_directory:$cache,defaults:{mode:$mode,exact:$exact,max_pages:$max_pages,max_credits:$max_credits,cache_enabled:$cache_enabled}}'
}

doctor_command() {
  local failed=0 cmd status
  printf '%s %s doctor (network-free)\n' "$APP_NAME" "$APP_VERSION"
  for cmd in bash curl jq sed awk grep sort; do if command -v "$cmd" >/dev/null 2>&1; then status=OK; else status=MISSING; failed=1; fi; printf '%-12s %s\n' "$cmd" "$status"; done
  for cmd in whois flock idn2 column sha256sum shasum shellcheck; do command -v "$cmd" >/dev/null 2>&1 && status=available || status=optional-missing; printf '%-12s %s\n' "$cmd" "$status"; done
  printf 'key source   %s (not read)\nnetwork      no request made\n' "$(safe_key_source)"
  return "$failed"
}

ui_init() {
  if [[ -t 1 && ${TERM:-dumb} != dumb && -z ${NO_COLOR:-} ]]; then
    COLOR_ENABLED=true
    UI_RESET=$'\033[0m'; UI_BOLD=$'\033[1m'; UI_DIM=$'\033[2m'
    UI_CYAN=$'\033[38;5;51m'; UI_BLUE=$'\033[38;5;75m'; UI_GREEN=$'\033[38;5;82m'
    UI_YELLOW=$'\033[38;5;220m'; UI_RED=$'\033[38;5;203m'
  fi
}

ui_clear() { $COLOR_ENABLED && printf '\033[2J\033[H' || printf '\n'; }
ui_rule() { printf '%s%s%s\n' "$UI_BLUE" '----------------------------------------------------------------' "$UI_RESET"; }
ui_title() { printf '%s%s%s%s\n' "$UI_BOLD" "$UI_CYAN" "$1" "$UI_RESET"; }
ui_option() { printf '  %s%2s%s  %s\n' "$UI_GREEN" "$1" "$UI_RESET" "$2"; }
ui_back() { printf '  %s99%s  Back\n' "$UI_YELLOW" "$UI_RESET"; }
ui_note() { printf '%s[i]%s %s\n' "$UI_BLUE" "$UI_RESET" "$1"; }
ui_error() { printf '%s[!]%s %s\n' "$UI_RED" "$UI_RESET" "$1" >&2; }
ui_prompt() {
  printf '%s> %s%s' "$UI_CYAN" "$UI_RESET" "$1"
  IFS= read -r UI_INPUT || UI_INPUT=99
  UI_INPUT=$(printf '%s' "$UI_INPUT" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')
}
ui_pause() {
  printf '\n%sPress Enter to continue...%s' "$UI_DIM" "$UI_RESET"
  IFS= read -r UI_INPUT || true
}
ui_header() {
  printf '%s%s' "$UI_CYAN" "$UI_BOLD"
  cat <<'ART'
 __        ___   _  ___ ___   ____  _____ ____ ___  _   _
 \ \      / / | | |/ _ \_ _| / ___||  ___|  _ \_ _|| | / /
  \ \ /\ / /| |_| | | | | |  \___ \| |_  | |_) | | | |/ /
   \ V  V / |  _  | |_| | |   ___) |  _| |  _ <| | |   <
    \_/\_/  |_| |_|\___/___| |____/|_|   |_| \_\___|_|\_\
ART
  printf '%s  WHOISFREAKS PIVOT CONSOLE  %s// authorized recon & information gathering%s\n' "$UI_GREEN" "$UI_DIM" "$UI_RESET"
  printf '%s  v%s  docs verified %s%s\n' "$UI_DIM" "$APP_VERSION" "$DOC_VERIFIED" "$UI_RESET"
}

interactive_reset_operation() {
  MODE=default; EXACT=true; PAGE=1; MAX_PAGES=1; MAX_CREDITS=$DEFAULT_MAX_CREDITS
  FORMAT=table; OUTPUT_PATH=""; PAID_MODE=false; ALL_PAGES=false; DRY_RUN=false
  ESTIMATE_ONLY=false; REFRESH=false; INTERACTIVE_APPROVED=false
}

interactive_run() {
  local label=$1
  shift
  printf '\n'
  if (INTERACTIVE_APPROVED=true; "$@"); then
    printf '\n%s[+]%s %s complete.\n' "$UI_GREEN" "$UI_RESET" "$label"
  else
    ui_error "$label did not complete. Review the message above."
  fi
  ui_pause
}

interactive_preview_reverse() {
  DRY_RUN=true
  NO_KEY_FILE=true
  reverse_command "$@"
}

interactive_seed_simple() {
  SEED_PIVOT_PROMPT=false
  seed_command "$@"
}

interactive_reverse_advanced() {
  local choice estimate
  ui_clear; ui_title "Advanced request options"; ui_rule
  ui_option 1 "Default mode - up to 50 detailed records"
  ui_option 2 "Mini mode - up to 100 compact records"
  ui_back; ui_prompt "Mode [1]: "; choice=${UI_INPUT:-1}
  case $choice in 1) MODE=default ;; 2) MODE=mini ;; 99) return 1 ;; *) ui_error "Using detailed default mode."; MODE=default ;; esac

  printf '\n'; ui_option 1 "Exact match (recommended)"; ui_option 2 "Pattern / fuzzy match"; ui_back
  ui_prompt "Matching [1]: "; choice=${UI_INPUT:-1}
  case $choice in 1) EXACT=true ;; 2) EXACT=false ;; 99) return 1 ;; *) ui_error "Using exact matching."; EXACT=true ;; esac

  ui_prompt "Starting page [1, or 99 to go back]: "; choice=${UI_INPUT:-1}
  [[ $choice == 99 ]] && return 1
  is_uint "$choice" && ((choice > 0)) && PAGE=$choice || PAGE=1
  ui_prompt "Pages to retrieve [1, max 20, 99 = back]: "; choice=${UI_INPUT:-1}
  [[ $choice == 99 ]] && return 1
  if is_uint "$choice" && ((choice >= 1 && choice <= 20)); then MAX_PAGES=$choice; else MAX_PAGES=1; fi
  if (( MAX_PAGES > 1 )); then PAID_MODE=true; estimate=$(estimate_credits reverse "$MAX_PAGES"); MAX_CREDITS=$estimate; fi

  printf '\n'; ui_title "Output"; ui_option 1 "Readable table"; ui_option 2 "Unique domains"; ui_option 3 "Normalized JSON"; ui_option 4 "CSV"; ui_option 5 "HTML report"; ui_option 6 "Raw provider JSON"; ui_back
  ui_prompt "Format [1]: "; choice=${UI_INPUT:-1}
  case $choice in 1) FORMAT=table ;; 2) FORMAT=domains ;; 3) FORMAT=json ;; 4) FORMAT=csv ;; 5) FORMAT=html ;; 6) FORMAT=raw ;; 99) return 1 ;; *) FORMAT=table ;; esac
  ui_prompt "Save path [Enter = terminal only, 99 = back]: "
  [[ $UI_INPUT == 99 ]] && return 1
  OUTPUT_PATH=$UI_INPUT
  return 0
}

interactive_reverse() {
  local choice type label value action estimate detail
  while :; do
    interactive_reset_operation
    ui_clear; ui_title "Reverse WHOIS"; ui_rule
    ui_option 1 "Email address"; ui_option 2 "Owner / registrant name"; ui_option 3 "Company / organization"; ui_option 4 "Domain keyword"; ui_back
    ui_prompt "Choose a search dimension: "; choice=$UI_INPUT
    case $choice in
      1) type=email; label="Email" ;; 2) type=owner; label="Owner" ;; 3) type=company; label="Company" ;; 4) type=keyword; label="Keyword" ;; 99) return ;; *) ui_error "Choose 1-4, or 99 to go back."; ui_pause; continue ;;
    esac
    ui_prompt "$label value [99 = back]: "; value=$UI_INPUT
    [[ $value == 99 ]] && continue
    [[ -n $value ]] || { ui_error "A value is required."; ui_pause; continue; }
    if $VERBOSE; then interactive_reverse_advanced || continue; fi
    estimate=$(estimate_credits reverse "$MAX_PAGES")
    detail="exact=$EXACT | mode=$MODE | page=$PAGE | pages=$MAX_PAGES | output=$FORMAT"
    ui_clear; ui_title "Review operation"; ui_rule
    printf '  Search     %s%s%s = %s%s%s\n' "$UI_BOLD" "$label" "$UI_RESET" "$UI_BOLD" "$value" "$UI_RESET"
    printf '  Settings   %s\n  Max cost   %s%s credit(s)%s\n  Cache      %s\n' "$detail" "$UI_YELLOW" "$estimate" "$UI_RESET" "$($CACHE_ENABLED && printf enabled || printf disabled)"
    printf '\n'; ui_option 1 "Run this request"; ui_option 2 "Preview only - no key, no network, no credits"; ui_back
    ui_prompt "Choose: "; action=$UI_INPUT
    case $action in
      1) interactive_run "Reverse WHOIS" reverse_command --type "$type" --value "$value"; return ;;
      2) interactive_run "Preview" interactive_preview_reverse --type "$type" --value "$value"; return ;;
      99) continue ;; *) ui_error "Nothing was sent."; ui_pause ;;
    esac
  done
}

interactive_seed() {
  local domain source_choice file
  while :; do
    interactive_reset_operation
    ui_clear; ui_title "Start from a domain"; ui_rule
    ui_note "Default: local whois -> role-aware pivots -> no paid request."
    ui_prompt "Domain [99 = back]: "; domain=$UI_INPUT
    [[ $domain == 99 ]] && return
    [[ -n $domain ]] || { ui_error "A domain is required."; ui_pause; continue; }
    if ! $VERBOSE; then interactive_run "Domain pivot extraction" interactive_seed_simple "$domain" --seed-source local; return; fi
    printf '\n'; ui_option 1 "Local whois (free, recommended)"; ui_option 2 "Existing WHOIS file"; ui_option 3 "Paste WHOIS through stdin"; ui_option 4 "WhoisFreaks Live WHOIS (1 credit)"; ui_back
    ui_prompt "Source [1]: "; source_choice=${UI_INPUT:-1}
    case $source_choice in
      1) interactive_run "Domain pivot extraction" seed_command "$domain" --seed-source local; return ;;
      2) ui_prompt "WHOIS file [99 = back]: "; file=$UI_INPUT; [[ $file == 99 ]] && continue; interactive_run "Domain pivot extraction" seed_command "$domain" --seed-source file --whois-file "$file"; return ;;
      3) ui_note "Paste the record, then press Ctrl-D."; interactive_run "Domain pivot extraction" seed_command "$domain" --seed-source stdin; return ;;
      4) ui_clear; ui_title "Review paid lookup"; printf '  Domain     %s\n  Max cost   %s1 credit%s\n\n' "$domain" "$UI_YELLOW" "$UI_RESET"; ui_option 1 "Run Live WHOIS"; ui_back; ui_prompt "Choose: "; [[ $UI_INPUT == 1 ]] && { interactive_run "Live WHOIS pivot extraction" seed_command "$domain" --seed-source api; return; } ;;
      99) return ;; *) ui_error "Choose 1-4, or 99."; ui_pause ;;
    esac
  done
}

interactive_parse() {
  local file
  while :; do
    ui_clear; ui_title "Parse a raw WHOIS record"; ui_rule; ui_note "Local operation: no API key and no credits."
    ui_prompt "File path [99 = back]: "; file=$UI_INPUT
    [[ $file == 99 ]] && return
    [[ -n $file ]] || { ui_error "A file path is required."; ui_pause; continue; }
    interactive_run "WHOIS parsing" parse_whois_command "$file"; return
  done
}

interactive_filter_field() {
  local choice
  UI_FIELD=""
  ui_clear; ui_title "Choose a local correlation field"; ui_rule
  ui_option 1 "Any email"; ui_option 2 "Any contact name"; ui_option 3 "Organization / company"; ui_option 4 "Phone"; ui_option 5 "City"; ui_option 6 "Country"; ui_option 7 "Registrar"; ui_option 8 "Nameserver"; ui_option 9 "Domain status"
  if $VERBOSE; then ui_option 10 "Registrant email"; ui_option 11 "Administrative email"; ui_option 12 "Technical email"; ui_option 13 "Billing email"; ui_option 14 "Street"; ui_option 15 "Postal code"; ui_option 16 "Registrar IANA ID"; ui_option 17 "Registry domain ID"; ui_option 18 "Creation date"; ui_option 19 "Update date"; ui_option 20 "Expiry date"; fi
  ui_back; ui_prompt "Field: "; choice=$UI_INPUT
  case $choice in 1) UI_FIELD=any_email ;; 2) UI_FIELD=any_contact_name ;; 3) UI_FIELD=organization ;; 4) UI_FIELD=phone ;; 5) UI_FIELD=city ;; 6) UI_FIELD=country ;; 7) UI_FIELD=registrar ;; 8) UI_FIELD=nameserver ;; 9) UI_FIELD=status ;; 10) $VERBOSE && UI_FIELD=registrant_email || UI_FIELD=invalid ;; 11) $VERBOSE && UI_FIELD=admin_email || UI_FIELD=invalid ;; 12) $VERBOSE && UI_FIELD=tech_email || UI_FIELD=invalid ;; 13) $VERBOSE && UI_FIELD=billing_email || UI_FIELD=invalid ;; 14) $VERBOSE && UI_FIELD=street || UI_FIELD=invalid ;; 15) $VERBOSE && UI_FIELD=postal_code || UI_FIELD=invalid ;; 16) $VERBOSE && UI_FIELD=iana_id || UI_FIELD=invalid ;; 17) $VERBOSE && UI_FIELD=registry_domain_id || UI_FIELD=invalid ;; 18) $VERBOSE && UI_FIELD=creation_date || UI_FIELD=invalid ;; 19) $VERBOSE && UI_FIELD=update_date || UI_FIELD=invalid ;; 20) $VERBOSE && UI_FIELD=expiry_date || UI_FIELD=invalid ;; 99) UI_FIELD=99 ;; *) UI_FIELD=invalid ;; esac
}

interactive_filter() {
  local file field value
  while :; do
    ui_clear; ui_title "Search saved results"; ui_rule; ui_note "Local correlation only. No API request will be made."
    ui_prompt "Normalized or raw JSON file [99 = back]: "; file=$UI_INPUT
    [[ $file == 99 ]] && return
    [[ -n $file ]] || { ui_error "A file path is required."; ui_pause; continue; }
    interactive_filter_field; field=$UI_FIELD
    [[ $field == 99 ]] && continue
    [[ $field != invalid && -n $field ]] || { ui_error "Invalid field choice."; ui_pause; continue; }
    ui_prompt "Value [99 = back]: "; value=$UI_INPUT
    [[ $value == 99 ]] && continue
    interactive_run "Local correlation" filter_command "$file" --field "$field" --value "$value"; return
  done
}

interactive_cache() {
  local choice key
  while :; do
    ui_clear; ui_title "Local cache"; ui_rule
    ui_option 1 "Statistics"; ui_option 2 "List cache keys"; ui_option 3 "Show safe metadata"; ui_option 4 "Purge cached results"; ui_back
    ui_prompt "Choose: "; choice=$UI_INPUT
    case $choice in
      1) cache_command stats; ui_pause ;; 2) cache_command list; ui_pause ;; 3) ui_prompt "SHA-256 cache key [99 = back]: "; key=$UI_INPUT; [[ $key != 99 ]] && { (cache_command show "$key") || ui_error "Cache entry not found."; ui_pause; } ;; 4) ui_title "Purge confirmation"; ui_option 1 "Purge all cached results"; ui_back; ui_prompt "Choose: "; [[ $UI_INPUT == 1 ]] && { (ASSUME_YES=true; cache_command purge) || true; ui_pause; } ;; 99) return ;; *) ui_error "Choose 1-4, or 99."; ui_pause ;;
    esac
  done
}

interactive_live_usage() {
  PAID_MODE=true
  credits_command --live
}

interactive_usage() {
  while :; do
    ui_clear; ui_title "API usage & safety"; ui_rule
    ui_option 1 "Current account usage (live Credit Usage API)"
    ui_option 2 "Documented price estimates (offline)"
    ui_back; ui_prompt "Choose: "
    case $UI_INPUT in
      1)
        ui_clear; ui_title "Review account-usage lookup"; ui_rule
        printf '  Key source  %s\n  Endpoint    WhoisFreaks Credit Usage API\n  Cost        %snot documented by the provider%s\n\n' "$(safe_key_source)" "$UI_YELLOW" "$UI_RESET"
        ui_option 1 "Query current account usage"; ui_back; ui_prompt "Choose: "
        [[ $UI_INPUT == 1 ]] && interactive_run "Account usage lookup" interactive_live_usage
        ;;
      2) ui_clear; ui_title "Documented price estimates"; ui_rule; credits_command --estimate-only; ui_pause ;;
      99) return ;;
      *) ui_error "Choose 1, 2, or 99."; ui_pause ;;
    esac
  done
}

interactive_info() {
  local screen=$1
  ui_clear
  case $screen in
    config) ui_title "Safe configuration"; ui_rule; config_command | jq -r '"  Version      \(.version)\n  Key source   \(.key_source)\n  Cache        \(.cache_directory)\n  Mode         \(.defaults.mode)\n  Exact        \(.defaults.exact)\n  Max pages    \(.defaults.max_pages)\n  Max credits  \(.defaults.max_credits)"' ;;
  esac
  ui_pause
}

interactive_menu() {
  [[ -t 0 && -t 1 ]] || { usage; return; }
  ui_init
  while :; do
    ui_clear; ui_header; ui_rule
    ui_option 1 "Quick Reverse WHOIS"; ui_option 2 "Start from a domain"; ui_option 3 "Parse a raw WHOIS file"; ui_option 4 "Search saved results"; ui_option 5 "Local cache"; ui_option 6 "API usage & safety"; ui_option 7 "Configuration"
    printf '\n  %s%s%s\n' "$UI_DIM" "$($VERBOSE && printf 'Advanced interaction enabled (-v)' || printf 'Simple mode - use ./whoisfreaks-pivot.sh -v for advanced choices')" "$UI_RESET"
    printf '  %s99%s  Exit\n' "$UI_YELLOW" "$UI_RESET"
    ui_prompt "Choose: "
    case $UI_INPUT in 1) interactive_reverse ;; 2) interactive_seed ;; 3) interactive_parse ;; 4) interactive_filter ;; 5) interactive_cache ;; 6) interactive_usage ;; 7) interactive_info config ;; 99|0|q|quit|exit) ui_clear; printf '%sStay curious. Verify every pivot.%s\n' "$UI_GREEN" "$UI_RESET"; return ;; *) ui_error "Choose 1-7, or 99 to exit."; ui_pause ;; esac
  done
}

PARSE_SHIFT=0
parse_common() {
  PARSE_SHIFT=1
  case $1 in
    --key-file) require_arg "$@"; KEY_FILE=$2; PARSE_SHIFT=2 ;; --no-key-file) NO_KEY_FILE=true ;; --show-key-source) SHOW_KEY_SOURCE=true ;;
    --dry-run) DRY_RUN=true ;; --yes|-y) ASSUME_YES=true ;; --max-pages) require_arg "$@"; MAX_PAGES=$2; PARSE_SHIFT=2 ;; --page) require_arg "$@"; PAGE=$2; PARSE_SHIFT=2 ;;
    --max-credits) require_arg "$@"; MAX_CREDITS=$2; PARSE_SHIFT=2 ;; --paid-mode) PAID_MODE=true ;; --all-pages) ALL_PAGES=true ;; --refresh) REFRESH=true ;;
    --cache-ttl) require_arg "$@"; CACHE_TTL=$2; PARSE_SHIFT=2 ;; --no-cache) CACHE_ENABLED=false ;; --estimate-only) ESTIMATE_ONLY=true ;;
    --mode) require_arg "$@"; MODE=$2; PARSE_SHIFT=2 ;; --exact) EXACT=true ;; --fuzzy|--no-exact) EXACT=false ;;
    --format) require_arg "$@"; FORMAT=$2; PARSE_SHIFT=2 ;; --output) require_arg "$@"; OUTPUT_PATH=$2; PARSE_SHIFT=2 ;; --output-dir) require_arg "$@"; OUTPUT_DIR=$2; PARSE_SHIFT=2 ;;
    --quiet) QUIET=true ;; -v|--verbose) VERBOSE=true ;; --debug) DEBUG=true ;; --retries) require_arg "$@"; RETRIES=$2; PARSE_SHIFT=2 ;; --redact-query) REDACT_QUERY=true ;;
    *) die "unknown option: $1" ;;
  esac
  [[ $MODE == default || $MODE == mini ]] || die "--mode must be default or mini"
  [[ $FORMAT =~ ^(table|domains|json|csv|html|raw)$ ]] || die "invalid --format"
  [[ -z $CACHE_TTL ]] || validate_range --cache-ttl "$CACHE_TTL" 0 31536000
  validate_range --retries "$RETRIES" 0 5
}

usage() { cat <<'HELP'
Usage: whoisfreaks-pivot.sh COMMAND [OPTIONS]

Commands:
  reverse --type TYPE --value VALUE   Search email, owner, company, or keyword
  seed DOMAIN                         Parse local WHOIS and identify safe pivots
  parse-whois FILE|-                  Parse a raw WHOIS record
  filter FILE --field FIELD --value V Filter normalized/saved JSON locally
  cache list|stats|purge|show KEY      Manage the local cache
  credits [--estimate-only|--live]     Show estimates; --live is explicit
  config                              Show non-secret configuration
  doctor                              Check dependencies without network access

Common safety options:
  --dry-run --yes --max-pages N --page N --max-credits N --paid-mode
  --all-pages --refresh --cache-ttl SECONDS --no-cache --estimate-only
  --key-file PATH --no-key-file --show-key-source
  --mode default|mini --exact --fuzzy --retries N
  --format table|domains|json|csv|html|raw --output PATH --output-dir PATH
  --quiet -v|--verbose --debug --redact-query

With no command, a number-driven interactive console is shown. Use 99 to go back.
Run `whoisfreaks-pivot.sh -v` for advanced interactive request and output choices.
HELP
}
reverse_help() { cat <<'HELP'
Usage: whoisfreaks-pivot.sh reverse --type email|owner|company|keyword --value VALUE [OPTIONS]
Exact matching and one page are the safe defaults. Mini returns up to 100 compact records/page;
default returns up to 50 detailed records/page. Each page currently costs 5 credits.
HELP
}
seed_help() { cat <<'HELP'
Usage: whoisfreaks-pivot.sh seed DOMAIN [--seed-source local|file|stdin|api] [--whois-file FILE]
Local whois is the default. API use is never a fallback and always requires confirmation.
HELP
}
filter_help() { cat <<'HELP'
Usage: whoisfreaks-pivot.sh filter FILE --field FIELD [--value VALUE] [--exact|--substring] [--from DATE] [--to DATE]
Fields: any_email, registrant_email, admin_email, tech_email, billing_email, any_contact_name,
organization, phone, street, city, postal_code, country, registrar, iana_id,
registry_domain_id, nameserver, status, creation_date, update_date, expiry_date.
This command is always local and never performs an API request.
HELP
}
credits_help() { cat <<'HELP'
Usage: whoisfreaks-pivot.sh credits [--estimate-only] [--live --paid-mode]
The Credit Usage endpoint cost is not stated in official documentation. Default is offline estimates.
HELP
}

main() {
  umask 077
  [[ ${BASH_VERSINFO[0]} -ge 5 ]] || die "Bash 5 or newer is required"
  while (($#)) && [[ $1 == -v || $1 == --verbose ]]; do VERBOSE=true; shift; done
  local command=${1:-}
  [[ -n $command ]] || { interactive_menu; return; }
  shift || true
  case $command in
    -h|--help|help) usage ;; --version|version) printf '%s %s\n' "$APP_NAME" "$APP_VERSION" ;;
    reverse) reverse_command "$@" ;; seed) seed_command "$@" ;; parse-whois) parse_whois_command "$@" ;; filter) filter_command "$@" ;;
    cache) cache_command "$@" ;; credits) credits_command "$@" ;; config) while (($#)); do parse_common "$@"; shift "$PARSE_SHIFT"; done; config_command ;;
    doctor) while (($#)); do parse_common "$@"; shift "$PARSE_SHIFT"; done; doctor_command ;;
    *) die "unknown command: $command (try --help)" ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
