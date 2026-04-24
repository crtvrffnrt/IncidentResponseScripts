#!/bin/bash
# urlir.sh - URL-focused Incident Response enrichment helper

export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"

set -o pipefail

API_KEY_FILE="/root/Tools/apikeys.txt"
[[ -f "$API_KEY_FILE" ]] && source "$API_KEY_FILE"

R='\033[0;31m'; LR='\033[1;31m'
G='\033[0;32m'; LG='\033[1;32m'
Y='\033[0;33m'; LY='\033[1;33m'
B='\033[0;34m'; LB='\033[1;34m'
M='\033[0;35m'; LM='\033[1;35m'
C='\033[0;36m'; LC='\033[1;36m'
W='\033[1;37m'; D='\033[2m'; NC='\033[0m'
BOLD='\033[1m'

SYM_INFO="[i]"; SYM_WARN="[!]"; SYM_ERR="[X]"; SYM_OK="[V]"; SYM_SCAN="[*]"
SYM_URL="[u]"; SYM_DOM="[d]"; SYM_IP="[ip]"; SYM_TIME="[t]"; SYM_CF="[cf]"

VERBOSE=false
TARGET_URL=""
INPUT_FILE=""
SCORE=0
ERRORS=()
SIGNALS=()
URL_RESULT_LINES=()
DOMAIN_RESULT_LINES=()
IP_RESULT_LINES=()

required_cmds=(jq dig curl sort grep sed awk base64 python3)
required_keys=(
    vtapi otxapi kasperskyapi threatfoxapi abusechapi
    ipinfoapi ipapisisapi abuseapi crowdsecapi hybridapi shdapi
    CLOUDFLARE_API CLOUDFLARE_ACCOUNT_ID
)

log_stat() { printf "  ${D}%-24s${NC} : %b\n" "$1" "$2"; }
draw_sep() { printf "  %b%s%b\n" "${D}" "----------------------------------------------------------------------------" "${NC}"; }
log_header() { echo -e "\n${LM}${SYM_SCAN}  $1 ${NC}"; draw_sep; }
add_score() { local points="${1:-0}"; local reason="${2:-}"; ((SCORE += points)); [[ -n "$reason" && "$points" -gt 0 ]] && SIGNALS+=("$reason"); }
add_error() { ERRORS+=("$1"); }
verbose() { [[ "$VERBOSE" == true ]] && echo -e "${M}[V]${NC} $1"; }

show_help() {
    echo -e "${LC}${SYM_SCAN} URL-IR${NC}"
    echo -e "${D}Usage:${NC} $0 [options] <URL>"
    echo -e "       $0 [options] -file URLs.txt"
    echo
    echo -e "${LC}Options:${NC}"
    echo "  -v, --verbose       Show extra source context"
    echo "  -file <path>        Scan one URL per non-empty line"
    echo "  -h, --help          Show this help"
    echo
    echo "Purpose: concise SOC triage for URLs using URL, domain, resolved-IP, and Cloudflare Radar signals."
    exit 0
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -v|--verbose) VERBOSE=true ;;
        -file|--file)
            shift
            [[ -z "${1:-}" ]] && { echo -e "${LR}${SYM_ERR} Missing file path after -file${NC}"; exit 1; }
            INPUT_FILE="$1"
            ;;
        -h|--help) show_help ;;
        -*)
            echo -e "${LR}${SYM_ERR} Unknown option:${NC} $1"
            show_help
            ;;
        *)
            if [[ -n "$TARGET_URL" ]]; then
                echo -e "${LR}${SYM_ERR} Only one URL is accepted. Use -file for multiple URLs.${NC}"
                exit 1
            fi
            TARGET_URL="$1"
            ;;
    esac
    shift
done

if [[ -n "$TARGET_URL" && -n "$INPUT_FILE" ]]; then
    echo -e "${LR}${SYM_ERR} Use either a single URL or -file, not both.${NC}"
    exit 1
fi
[[ -z "$TARGET_URL" && -z "$INPUT_FILE" ]] && show_help
if [[ -n "$INPUT_FILE" && ! -r "$INPUT_FILE" ]]; then
    echo -e "${LR}${SYM_ERR} URL file is not readable:${NC} $INPUT_FILE"
    exit 1
fi

for cmd in "${required_cmds[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${LR}${SYM_ERR} Missing dependency:${NC} $cmd"
        exit 1
    fi
done

missing_keys=()
for key in "${required_keys[@]}"; do
    if [[ -z "${!key:-}" ]]; then
        missing_keys+=("$key")
    fi
done
if [[ ${#missing_keys[@]} -gt 0 ]]; then
    echo -e "${LR}${SYM_ERR} Missing API keys in ${API_KEY_FILE}:${NC} ${missing_keys[*]}"
    exit 1
fi

uri_encode() {
    python3 - "$1" <<'PY'
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
}

json_string() {
    jq -Rn --arg value "$1" '$value'
}

url_id() {
    python3 - "$1" <<'PY'
import base64, sys
raw = base64.urlsafe_b64encode(sys.argv[1].encode()).decode()
print(raw.rstrip("="))
PY
}

parse_url() {
    python3 - "$1" <<'PY'
import sys
from urllib.parse import urlparse
url = sys.argv[1]
if "://" not in url:
    url = "https://" + url
p = urlparse(url)
host = (p.hostname or "").strip(".").lower()
labels = [x for x in host.split(".") if x]
root = host
if len(labels) >= 2:
    root = ".".join(labels[-2:])
print(url)
print(host)
print(root)
PY
}

http_request() {
    local timeout="$1"
    shift
    local tmp
    tmp=$(mktemp)
    CURL_STATUS=$(curl -sS --connect-timeout 5 --max-time "$timeout" -o "$tmp" -w "%{http_code}" "$@" 2>/dev/null)
    CURL_RC=$?
    CURL_DATA=$(cat "$tmp")
    rm -f "$tmp"
    [[ "$CURL_RC" -eq 0 ]]
}

resolve_final_url() {
    local input_url="$1"
    local response rc http_code final_url num_redirects

    response=$(curl -sS -L --max-redirs 10 --connect-timeout 5 --max-time 20 -o /dev/null \
        -w '%{http_code}\t%{url_effective}\t%{num_redirects}' "$input_url" 2>/dev/null)
    rc=$?
    if [[ "$rc" -ne 0 || -z "$response" ]]; then
        printf '000\t%s\t0\n' "$input_url"
        return 1
    fi

    IFS=$'\t' read -r http_code final_url num_redirects <<< "$response"
    [[ -z "$final_url" ]] && final_url="$input_url"
    [[ -z "$num_redirects" ]] && num_redirects=0
    printf '%s\t%s\t%s\n' "${http_code:-000}" "$final_url" "$num_redirects"
}

safe_jq() {
    local filter="$1"
    local default="$2"
    jq -r "$filter // \"$default\"" 2>/dev/null <<< "${3:-$CURL_DATA}"
}

draw_traffic_light() {
    local score=$1
    local state color
    if [[ $score -ge 800 ]]; then
        state="MALICIOUS"; color="${LR}"
    elif [[ $score -ge 250 ]]; then
        state="SUSPICIOUS"; color="${LY}"
    else
        state="CLEAN"; color="${LG}"
    fi

    echo -e "\n  ${BOLD}FINAL ASSESSMENT${NC}"
    echo -e "  ${D}+---------------------+${NC}"
    echo -e "  ${D}|${NC} ${LR}!${NC} ${D}|${NC} ${D}Score :${NC} ${W}${score}${NC}"
    echo -e "  ${D}|${NC} ${LY}!${NC} ${D}|${NC} ${D}State :${NC} ${color}${state}${NC}"
    echo -e "  ${D}|${NC} ${LG}!${NC} ${D}|${NC}"
    echo -e "  ${D}+---------------------+${NC}"
}

vt_url_check() {
    local url="$1"
    local id mal susp harmless undetected total
    id=$(url_id "$url")
    http_request 12 -H "x-apikey: $vtapi" "https://www.virustotal.com/api/v3/urls/$id" || {
        add_error "VirusTotal URL: request failed"
        return
    }

    if [[ "$CURL_STATUS" == "200" && "$(jq -r '.data.id // empty' <<< "$CURL_DATA" 2>/dev/null)" != "" ]]; then
        mal=$(safe_jq '.data.attributes.last_analysis_stats.malicious' 0)
        susp=$(safe_jq '.data.attributes.last_analysis_stats.suspicious' 0)
        harmless=$(safe_jq '.data.attributes.last_analysis_stats.harmless' 0)
        undetected=$(safe_jq '.data.attributes.last_analysis_stats.undetected' 0)
    else
        verbose "VirusTotal has no URL object, submitting URL analysis."
        http_request 12 -X POST -H "x-apikey: $vtapi" --data-urlencode "url=$url" "https://www.virustotal.com/api/v3/urls" || {
            add_error "VirusTotal URL: submit failed"
            return
        }
        local analysis_id
        analysis_id=$(safe_jq '.data.id' "")
        if [[ -z "$analysis_id" ]]; then
            add_error "VirusTotal URL: no cached result and submit did not return analysis id"
            return
        fi
        sleep 12
        for _ in 1 2 3 4; do
            http_request 12 -H "x-apikey: $vtapi" "https://www.virustotal.com/api/v3/analyses/$analysis_id" || break
            [[ "$(safe_jq '.data.attributes.status' "")" == "completed" ]] && break
            sleep 5
        done
        mal=$(safe_jq '.data.attributes.stats.malicious' 0)
        susp=$(safe_jq '.data.attributes.stats.suspicious' 0)
        harmless=$(safe_jq '.data.attributes.stats.harmless' 0)
        undetected=$(safe_jq '.data.attributes.stats.undetected' 0)
    fi

    total=$((mal + susp + harmless + undetected))
    add_score $((mal * 220 + susp * 80)) "VirusTotal URL detections ${mal}/${total} malicious, ${susp} suspicious"
    URL_RESULT_LINES+=("VirusTotal URL|${mal} malicious, ${susp} suspicious (${total} engines)")
}

vt_domain_check() {
    local domain="$1" label="$2"
    [[ -z "$domain" ]] && return
    http_request 12 -H "x-apikey: $vtapi" "https://www.virustotal.com/api/v3/domains/$domain" || {
        add_error "VirusTotal domain ${label}: request failed"
        return
    }
    [[ "$CURL_STATUS" != "200" ]] && { add_error "VirusTotal domain ${label}: HTTP $CURL_STATUS"; return; }
    local mal susp rep cats
    mal=$(safe_jq '.data.attributes.last_analysis_stats.malicious' 0)
    susp=$(safe_jq '.data.attributes.last_analysis_stats.suspicious' 0)
    rep=$(safe_jq '.data.attributes.reputation' 0)
    cats=$(jq -r '.data.attributes.categories // {} | to_entries | map(.value) | unique | .[0:3] | join(", ")' 2>/dev/null <<< "$CURL_DATA")
    add_score $((mal * 120 + susp * 50)) "VirusTotal ${label} detections ${mal} malicious, ${susp} suspicious"
    [[ "$rep" =~ ^- ]] && add_score 100 "VirusTotal ${label} negative community reputation ${rep}"
    DOMAIN_RESULT_LINES+=("VT ${label}|${mal} malicious, ${susp} suspicious, rep ${rep}${cats:+, $cats}")
}

kaspersky_check() {
    local type="$1" value="$2" label="$3" endpoint
    [[ "$type" == "url" ]] && endpoint="url" || endpoint="$type"
    http_request 12 -G -H "x-api-key: $kasperskyapi" --data-urlencode "request=$value" "https://opentip.kaspersky.com/api/v1/search/$endpoint" || {
        add_error "Kaspersky ${label}: request failed"
        return
    }
    [[ "$CURL_STATUS" != "200" ]] && { add_error "Kaspersky ${label}: HTTP $CURL_STATUS"; return; }
    local zone files urls cats
    zone=$(safe_jq '.Zone' "Unknown")
    files=$(jq -r '(.UrlGeneralInfo.FilesCount // .DomainGeneralInfo.FilesCount // 0)' 2>/dev/null <<< "$CURL_DATA")
    urls=$(jq -r '(.DomainGeneralInfo.UrlsCount // 0)' 2>/dev/null <<< "$CURL_DATA")
    cats=$(jq -r '(.UrlGeneralInfo.Categories // .DomainGeneralInfo.Categories // []) | .[0:3] | join(", ")' 2>/dev/null <<< "$CURL_DATA")
    case "$zone" in
        Red) add_score 700 "Kaspersky ${label} Red zone" ;;
        Orange) add_score 350 "Kaspersky ${label} Orange zone" ;;
        Yellow) add_score 150 "Kaspersky ${label} Yellow zone" ;;
    esac
    if [[ "$label" == "URL" ]]; then
        URL_RESULT_LINES+=("Kaspersky URL|Zone ${zone}, files ${files}${cats:+, $cats}")
    else
        DOMAIN_RESULT_LINES+=("Kaspersky ${label}|Zone ${zone}, files ${files}, URLs ${urls}${cats:+, $cats}")
    fi
}

urlhaus_check() {
    local url="$1"
    http_request 12 -X POST -H "Auth-Key: $abusechapi" --data-urlencode "url=$url" "https://urlhaus-api.abuse.ch/v1/url/" || {
        add_error "URLhaus: request failed"
        return
    }
    [[ "$CURL_STATUS" != "200" ]] && { add_error "URLhaus: HTTP $CURL_STATUS"; return; }
    local status threat tags
    status=$(safe_jq '.query_status' "unknown")
    if [[ "$status" == "ok" ]]; then
        local url_status
        url_status=$(safe_jq '.url_status' "unknown")
        threat=$(safe_jq '.threat' "unknown")
        tags=$(jq -r '.tags // [] | join(",")' 2>/dev/null <<< "$CURL_DATA")
        [[ "$url_status" == "online" ]] && add_score 900 "URLhaus active malware URL"
        [[ "$url_status" != "online" ]] && add_score 500 "URLhaus historical malware URL (${url_status})"
        URL_RESULT_LINES+=("URLhaus|${url_status} ${threat}${tags:+, $tags}")
    else
        URL_RESULT_LINES+=("URLhaus|no result")
    fi
}

threatfox_check() {
    local value="$1" label="$2"
    local payload
    payload=$(jq -n --arg ioc "$value" '{query:"search_ioc", search_term:$ioc, exact_match:true}')
    http_request 12 -X POST -H "Auth-Key: $threatfoxapi" -H "Content-Type: application/json" -d "$payload" "https://threatfox-api.abuse.ch/api/v1/" || {
        add_error "ThreatFox ${label}: request failed"
        return
    }
    [[ "$CURL_STATUS" != "200" ]] && { add_error "ThreatFox ${label}: HTTP $CURL_STATUS"; return; }
    local status conf malware threat
    status=$(safe_jq '.query_status' "unknown")
    if [[ "$status" == "ok" ]]; then
        conf=$(safe_jq '.data[0].confidence_level' 0)
        malware=$(safe_jq '.data[0].malware_printable' "unknown")
        threat=$(safe_jq '.data[0].threat_type' "unknown")
        add_score $((conf * 6)) "ThreatFox ${label} hit ${malware} confidence ${conf}"
        [[ "$label" == "URL" ]] && URL_RESULT_LINES+=("ThreatFox URL|${threat}, ${malware}, confidence ${conf}") || DOMAIN_RESULT_LINES+=("ThreatFox ${label}|${threat}, ${malware}, confidence ${conf}")
    else
        [[ "$label" == "URL" ]] && URL_RESULT_LINES+=("ThreatFox URL|no result") || DOMAIN_RESULT_LINES+=("ThreatFox ${label}|no result")
    fi
}

otx_check() {
    local type="$1" value="$2" label="$3" encoded endpoint
    encoded=$(uri_encode "$value")
    [[ "$type" == "url" ]] && endpoint="url/$encoded/general" || endpoint="domain/$encoded/general"
    http_request 12 -H "X-OTX-API-KEY: $otxapi" "https://otx.alienvault.com/api/v1/indicators/$endpoint" || {
        add_error "OTX ${label}: request failed"
        return
    }
    [[ "$CURL_STATUS" != "200" ]] && { add_error "OTX ${label}: HTTP $CURL_STATUS"; return; }
    local pulses sections
    pulses=$(safe_jq '.pulse_info.count' 0)
    sections=$(jq -r '.sections // [] | .[0:5] | join(",")' 2>/dev/null <<< "$CURL_DATA")
    add_score $((pulses * 80)) "OTX ${label} in ${pulses} pulse(s)"
    [[ "$label" == "URL" ]] && URL_RESULT_LINES+=("OTX URL|${pulses} pulses${sections:+, $sections}") || DOMAIN_RESULT_LINES+=("OTX ${label}|${pulses} pulses${sections:+, $sections}")
}

cloudflare_check() {
    local url="$1"
    http_request 10 -H "Authorization: Bearer $CLOUDFLARE_API" "https://api.cloudflare.com/client/v4/user/tokens/verify" || {
        add_error "Cloudflare Radar: token verify failed, skipped"
        return
    }
    if [[ "$(jq -r '.success // false' 2>/dev/null <<< "$CURL_DATA")" != "true" ]]; then
        add_error "Cloudflare Radar: token invalid, skipped"
        return
    fi

    local query encoded scan_id search_path cf_source="existing"
    query="task.url:\"$url\" OR page.url:\"$url\""
    encoded=$(uri_encode "$query")
    search_path="https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/urlscanner/v2/search?q=$encoded&size=5"
    http_request 12 -H "Authorization: Bearer $CLOUDFLARE_API" "$search_path" || {
        add_error "Cloudflare Radar: search failed"
        return
    }
    if [[ "$CURL_STATUS" == "200" ]]; then
        scan_id=$(jq -r '
            [
                (.results[]? | select(.task.url == $url or .page.url == $url) | (.task.uuid // .uuid // ._id)),
                ((.result | objects | .results[]?) | select(.task.url == $url or .page.url == $url) | (.task.uuid // .uuid // ._id)),
                (.results[]? | (.task.uuid // .uuid // ._id)),
                ((.result | objects | .results[]?) | (.task.uuid // .uuid // ._id))
            ] | map(select(. != null and . != "")) | .[0] // empty
        ' --arg url "$url" 2>/dev/null <<< "$CURL_DATA")
    fi

    if [[ -z "$scan_id" ]]; then
        local payload
        payload=$(jq -n --arg url "$url" '{url:$url, visibility:"Unlisted"}')
        http_request 12 -X POST -H "Authorization: Bearer $CLOUDFLARE_API" -H "Content-Type: application/json" -d "$payload" "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/urlscanner/v2/scan" || {
            add_error "Cloudflare Radar: submit failed"
            return
        }
        if [[ "$CURL_STATUS" != "200" && "$CURL_STATUS" != "409" ]]; then
            add_error "Cloudflare Radar: submit HTTP $CURL_STATUS"
            return
        fi
        cf_source="created"
        scan_id=$(jq -r '
            .uuid //
            (.result | objects | .uuid) //
            (.result | objects | .tasks[0].uuid) //
            .tasks[0].uuid //
            (.api | strings | capture("/result/(?<id>[A-Za-z0-9-]+)$").id) //
            empty
        ' 2>/dev/null <<< "$CURL_DATA")
    fi

    [[ -z "$scan_id" ]] && { add_error "Cloudflare Radar: no scan id returned"; return; }

    local poll_count=0 result_ready=false
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        ((poll_count++))
        http_request 20 -H "Authorization: Bearer $CLOUDFLARE_API" "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/urlscanner/v2/result/$scan_id" || {
            add_error "Cloudflare Radar: result request failed"
            return
        }
        if [[ "$CURL_STATUS" == "200" ]]; then
            result_ready=true
            break
        fi
        if [[ "$CURL_STATUS" != "404" ]]; then
            if [[ "$cf_source" == "existing" ]]; then
                scan_id=""
                break
            fi
            add_error "Cloudflare Radar: result HTTP $CURL_STATUS"
            return
        fi
        if [[ "$cf_source" == "existing" ]]; then
            scan_id=""
            break
        fi
        sleep 12
    done

    if [[ "$result_ready" != true && "$cf_source" == "existing" ]]; then
        local payload
        payload=$(jq -n --arg url "$url" '{url:$url, visibility:"Unlisted"}')
        http_request 12 -X POST -H "Authorization: Bearer $CLOUDFLARE_API" -H "Content-Type: application/json" -d "$payload" "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/urlscanner/v2/scan" || {
            add_error "Cloudflare Radar: submit failed"
            return
        }
        if [[ "$CURL_STATUS" != "200" && "$CURL_STATUS" != "409" ]]; then
            add_error "Cloudflare Radar: submit HTTP $CURL_STATUS"
            return
        fi
        cf_source="created"
        scan_id=$(jq -r '
            .uuid //
            (.result | objects | .uuid) //
            (.result | objects | .tasks[0].uuid) //
            .tasks[0].uuid //
            (.api | strings | capture("/result/(?<id>[A-Za-z0-9-]+)$").id) //
            empty
        ' 2>/dev/null <<< "$CURL_DATA")
        [[ -z "$scan_id" ]] && { add_error "Cloudflare Radar: no scan id returned"; return; }

        poll_count=0
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            ((poll_count++))
            http_request 20 -H "Authorization: Bearer $CLOUDFLARE_API" "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/urlscanner/v2/result/$scan_id" || {
                add_error "Cloudflare Radar: result request failed"
                return
            }
            if [[ "$CURL_STATUS" == "200" ]]; then
                result_ready=true
                break
            fi
            [[ "$CURL_STATUS" != "404" ]] && { add_error "Cloudflare Radar: result HTTP $CURL_STATUS"; return; }
            sleep 12
        done
    fi
    [[ "$result_ready" != true ]] && { add_error "Cloudflare Radar: result not ready after ${poll_count} polls"; return; }

    local cf_filter='
        def root:
            if (.result | type) == "object" then .result
            elif ((.task? != null) or (.page? != null) or (.verdicts? != null)) then .
            elif (.data | type) == "object" and ((.data.requests? != null) or (.data.task? != null)) then .data
            else .
            end;
        root
    '
    local malicious phishing_count final_url final_ip rank categories url_risks reqs domains status_codes redirects cf_malicious secure_pct report_url
    malicious=$(jq -r "${cf_filter} | .verdicts.overall.malicious // false" 2>/dev/null <<< "$CURL_DATA")
    phishing_count=$(jq -r "${cf_filter} | (((.meta.processors.phishing.data // []) | length) + ((.meta.processors.phishing_v2.data // []) | length))" 2>/dev/null <<< "$CURL_DATA")
    cf_malicious=$(jq -r "${cf_filter} | .stats.malicious // 0" 2>/dev/null <<< "$CURL_DATA")
    final_url=$(jq -r "${cf_filter} | .page.url // (first(.data.requests[]? | select(.request.primaryRequest == true or .request.type == \"document\") | .response.response.url? // .request.request.url?) // empty)" 2>/dev/null <<< "$CURL_DATA")
    final_ip=$(jq -r "${cf_filter} | .page.ip // (first(.data.requests[]?.response.response.remoteIPAddress? // .data.requests[]?.request.redirectResponse.remoteIPAddress?) // empty)" 2>/dev/null <<< "$CURL_DATA")
    rank=$(jq -r "${cf_filter} | (.meta.processors.radarRank.data[0].rank // .meta.processors.radarRank.data[0].bucket // empty)" 2>/dev/null <<< "$CURL_DATA")
    categories=$(jq -r "${cf_filter} | [.meta.processors.domainCategories.data[]? | select(.isPrimary == true) | .content[]?.name] | unique | .[0:3] | join(\",\")" 2>/dev/null <<< "$CURL_DATA")
    url_risks=$(jq -r "${cf_filter} | [.meta.processors.urlCategories.data[]?.risks[]?] | unique | .[0:3] | join(\",\")" 2>/dev/null <<< "$CURL_DATA")
    reqs=$(jq -r "${cf_filter} | (.data.requests // []) | length" 2>/dev/null <<< "$CURL_DATA")
    domains=$(jq -r "${cf_filter} | (.lists.domains // []) | length" 2>/dev/null <<< "$CURL_DATA")
    status_codes=$(jq -r "${cf_filter} | [.data.requests[]?.response.response.status?] | unique | .[0:6] | join(\",\")" 2>/dev/null <<< "$CURL_DATA")
    redirects=$(jq -r "${cf_filter} | [ .data.requests[]? | select(.request.redirectResponse.status? != null) ] | length" 2>/dev/null <<< "$CURL_DATA")
    secure_pct=$(jq -r "${cf_filter} | .stats.securePercentage // empty" 2>/dev/null <<< "$CURL_DATA")
    report_url=$(jq -r "${cf_filter} | .task.reportURL // empty" 2>/dev/null <<< "$CURL_DATA")
    [[ "$malicious" == "true" ]] && add_score 800 "Cloudflare Radar malicious verdict"
    [[ "$phishing_count" =~ ^[0-9]+$ && "$phishing_count" -gt 0 ]] && add_score 600 "Cloudflare Radar phishing signal count ${phishing_count}"
    [[ "$cf_malicious" =~ ^[0-9]+$ && "$cf_malicious" -gt 0 ]] && add_score $((cf_malicious * 250)) "Cloudflare Radar malicious request count ${cf_malicious}"
    [[ -n "$url_risks" ]] && add_score 300 "Cloudflare Radar URL risk ${url_risks}"
    URL_RESULT_LINES+=("Cloudflare Radar|${cf_source}, malicious=${malicious}, phishing=${phishing_count}, badreq=${cf_malicious}, requests=${reqs}, domains=${domains}${redirects:+, redirects ${redirects}}${status_codes:+, HTTP ${status_codes}}${final_ip:+, final IP $final_ip}${secure_pct:+, TLS ${secure_pct}%}${rank:+, rank $rank}${url_risks:+, risks $url_risks}${categories:+, $categories}")
    [[ -n "$final_url" && "$final_url" != "$url" ]] && URL_RESULT_LINES+=("Cloudflare Final URL|$final_url")
    [[ "$VERBOSE" == true && -n "$report_url" ]] && URL_RESULT_LINES+=("Cloudflare Report|$report_url")
}

resolved_ip_check() {
    local host="$1"
    if is_ip_literal "$host"; then
        resolved_ips=("$host")
    else
        mapfile -t resolved_ips < <({ dig +short A "$host"; dig +short AAAA "$host"; } | grep -E '^[0-9a-fA-F:.]+$' | sort -u)
    fi
    if [[ ${#resolved_ips[@]} -eq 0 ]]; then
        IP_RESULT_LINES+=("DNS|no A/AAAA record found")
        add_score 80 "DNS did not resolve"
        return
    fi
    local ip="${resolved_ips[0]}"
    local more=""
    [[ ${#resolved_ips[@]} -gt 1 ]] && more=" (+$(( ${#resolved_ips[@]} - 1 )) more)"
    if is_ip_literal "$host"; then
        IP_RESULT_LINES+=("IP Literal|$ip")
    else
        IP_RESULT_LINES+=("DNS|$host -> $ip$more")
    fi

    local country asn org
    http_request 10 "https://ipinfo.io/$ip?token=$ipinfoapi" && {
        country=$(safe_jq '.country' "N/A")
        asn=$(safe_jq '.org' "N/A")
        IP_RESULT_LINES+=("IPInfo|${country}, ${asn}")
    } || add_error "IPInfo: request failed"

    http_request 10 -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=$ip" -H "Key: $abuseapi" -H "Accept: application/json" && {
        local abuse
        abuse=$(safe_jq '.data.abuseConfidenceScore' 0)
        add_score $((abuse * 4)) "AbuseIPDB resolved IP confidence ${abuse}"
        IP_RESULT_LINES+=("AbuseIPDB|confidence ${abuse}%")
    } || add_error "AbuseIPDB: request failed"

    http_request 10 -H "x-apikey: $vtapi" "https://www.virustotal.com/api/v3/ip_addresses/$ip" && {
        local mal susp
        mal=$(safe_jq '.data.attributes.last_analysis_stats.malicious' 0)
        susp=$(safe_jq '.data.attributes.last_analysis_stats.suspicious' 0)
        add_score $((mal * 120 + susp * 40)) "VirusTotal resolved IP ${mal} malicious, ${susp} suspicious"
        IP_RESULT_LINES+=("VirusTotal IP|${mal} malicious, ${susp} suspicious")
    } || add_error "VirusTotal IP: request failed"

    http_request 10 -H "x-api-key: $crowdsecapi" "https://cti.api.crowdsec.net/v2/smoke/$ip" && {
        local rep
        rep=$(safe_jq '.reputation' "safe")
        [[ "$rep" == "malicious" ]] && add_score 400 "CrowdSec resolved IP malicious"
        IP_RESULT_LINES+=("CrowdSec|${rep}")
    } || add_error "CrowdSec: request failed"

    http_request 10 "https://api.shodan.io/shodan/host/$ip?key=$shdapi" && {
        local tags ports
        tags=$(jq -r '.tags // [] | join(",")' 2>/dev/null <<< "$CURL_DATA")
        ports=$(jq -r '.ports // [] | .[0:8] | join(",")' 2>/dev/null <<< "$CURL_DATA")
        [[ "$tags" == *"malware"* || "$tags" == *"vpn"* || "$tags" == *"tor"* ]] && add_score 180 "Shodan resolved IP tag ${tags}"
        IP_RESULT_LINES+=("Shodan|ports ${ports:-none}${tags:+, tags $tags}")
    } || add_error "Shodan: request failed"
}

print_lines() {
    local -n arr="$1"
    local item key val
    for item in "${arr[@]}"; do
        key="${item%%|*}"
        val="${item#*|}"
        log_stat "$key" "$val"
    done
}

is_ip_literal() {
    local value="$1"
    [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$value" == *:* ]]
}

print_banner() {
    echo -e "${LM}$(cat <<'EOF'
██╗   ██╗██████╗ ██╗         ██╗██████╗
██║   ██║██╔══██╗██║         ██║██╔══██╗
██║   ██║██████╔╝██║         ██║██████╔╝
██║   ██║██╔══██╗██║         ██║██╔══██╗
╚██████╔╝██║  ██║███████╗    ██║██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝╚═╝  ╚═╝
EOF
)${NC}  ${D}URL Incident Response${NC}"
}

scan_url() {
    local input_url="$1"
    local parsed target_url scan_url_target scan_http_code redirect_hops input_host input_root host root_domain is_host_ip redirected

    SCORE=0
    ERRORS=()
    SIGNALS=()
    URL_RESULT_LINES=()
    DOMAIN_RESULT_LINES=()
    IP_RESULT_LINES=()

    mapfile -t parsed < <(parse_url "$input_url")
    target_url="${parsed[0]}"
    input_host="${parsed[1]}"
    input_root="${parsed[2]}"
    scan_url_target="$target_url"
    scan_http_code="000"
    redirect_hops=0
    redirected=false
    if [[ -z "$input_host" ]]; then
        echo -e "${LR}${SYM_ERR} Invalid URL:${NC} $target_url"
        return 1
    fi

    redirect_info=$(resolve_final_url "$target_url")
    IFS=$'\t' read -r scan_http_code scan_url_target redirect_hops <<< "$redirect_info"
    if [[ -n "$scan_url_target" && "$scan_url_target" != "$target_url" ]]; then
        redirected=true
    fi
    scan_url_target="${scan_url_target:-$target_url}"
    [[ -z "$redirect_hops" ]] && redirect_hops=0

    mapfile -t parsed < <(parse_url "$scan_url_target")
    host="${parsed[1]}"
    root_domain="${parsed[2]}"
    is_host_ip=false
    if is_ip_literal "$host"; then
        is_host_ip=true
        root_domain="$host"
    fi

    log_header "Target"
    log_stat "${SYM_URL} URL" "${W}${target_url}${NC}"
    if [[ "$redirected" == true ]]; then
        log_stat "${SYM_URL} Final URL" "${W}${scan_url_target}${NC}"
        log_stat "${SYM_URL} Redirect" "${Y}${redirect_hops} hop(s)${NC}"
        log_stat "${SYM_DOM} Input Host" "${LC}${input_host}${NC}"
        [[ "$input_root" != "$input_host" ]] && log_stat "${SYM_DOM} Input Root Domain" "${LC}${input_root}${NC}"
    fi
    [[ "$scan_http_code" != "000" ]] && log_stat "${SYM_URL} Final HTTP" "${W}${scan_http_code}${NC}"
    log_stat "${SYM_DOM} Host" "${LC}${host}${NC}"
    [[ "$root_domain" != "$host" ]] && log_stat "${SYM_DOM} Root Domain" "${LC}${root_domain}${NC}"

    log_header "Resolved IP Context"
    resolved_ip_check "$host"
    print_lines IP_RESULT_LINES

    log_header "URL Reputation"
    vt_url_check "$scan_url_target"
    urlhaus_check "$scan_url_target"
    kaspersky_check "url" "$scan_url_target" "URL"
    threatfox_check "$scan_url_target" "URL"
    otx_check "url" "$scan_url_target" "URL"
    cloudflare_check "$scan_url_target"
    print_lines URL_RESULT_LINES

    log_header "Host And Domain Reputation"
    if [[ "$is_host_ip" == true ]]; then
        DOMAIN_RESULT_LINES+=("Domain Context|IP-literal URL, domain checks skipped")
    else
        vt_domain_check "$host" "host"
        kaspersky_check "domain" "$host" "host"
        threatfox_check "$host" "host"
        otx_check "domain" "$host" "host"
        if [[ "$root_domain" != "$host" ]]; then
            vt_domain_check "$root_domain" "root"
            kaspersky_check "domain" "$root_domain" "root"
            threatfox_check "$root_domain" "root"
            otx_check "domain" "$root_domain" "root"
        fi
    fi
    print_lines DOMAIN_RESULT_LINES

    draw_traffic_light "$SCORE"

    if [[ ${#SIGNALS[@]} -gt 0 ]]; then
        log_header "Why"
        printf "  %s\n" "${SIGNALS[@]}" | sed 's/^/  - /'
    fi

    if [[ ${#ERRORS[@]} -gt 0 ]]; then
        log_header "Source Errors"
        printf "  ${LY}${SYM_WARN}${NC} %s\n" "${ERRORS[@]}"
    fi
}

print_banner
if [[ -n "$INPUT_FILE" ]]; then
    mapfile -t TARGET_URLS < <(grep -vE '^[[:space:]]*($|#)' "$INPUT_FILE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [[ ${#TARGET_URLS[@]} -eq 0 ]]; then
        echo -e "${LR}${SYM_ERR} URL file contains no scan candidates:${NC} $INPUT_FILE"
        exit 1
    fi
    for target in "${TARGET_URLS[@]}"; do
        scan_url "$target"
    done
else
    scan_url "$TARGET_URL"
fi

echo -e "\n${D}${SYM_SCAN} URL audit completed.${NC}"
