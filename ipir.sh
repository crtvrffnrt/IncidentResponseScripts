#!/bin/bash
# ipir.sh - ASCII-safe IP-IR tool

export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"

# --- Configuration & Dependencies ---
API_KEY_FILE="/root/dev/ir/apikeys.txt"
[[ -f "$API_KEY_FILE" ]] && source "$API_KEY_FILE"

for cmd in jq dig curl sort grep whois; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: Dependency '$cmd' missing. Install it to proceed."
        exit 1
    fi
done

# --- ANSI Futuristic Colors & Symbols ---
R='\033[0;31m'; LR='\033[1;31m'
G='\033[0;32m'; LG='\033[1;32m'
Y='\033[0;33m'; LY='\033[1;33m'
B='\033[0;34m'; LB='\033[1;34m'
M='\033[0;35m'; LM='\033[1;35m'
C='\033[0;36m'; LC='\033[1;36m'
W='\033[1;37m'; D='\033[2m'; NC='\033[0m'
BOLD='\033[1m'

# Universal Symbols (ASCII-safe)
SYM_INFO="[i]"; SYM_WARN="[!]"; SYM_ERR="[X]"; SYM_OK="[V]"; SYM_SCAN="[*]"; SYM_SHIELD="[S]"
SYM_LOC="[L]"; SYM_NET="[N]"; SYM_VPN="(V)"; SYM_TOR="(T)"; SYM_PROXY="(P)"
SYM_MOB="(m)"; SYM_DC="(D)"; SYM_TIME="[t]"; SYM_FILE="[f]"; SYM_WEB="[w]"

# --- Utility Functions ---
log_verbose() { [[ "$VERBOSE" == true ]] && echo -e "${M}[V]${NC} $1"; }
log_stat() { printf "  ${D}%-22s${NC} : %b\n" "$1" "$2"; }
draw_sep() { printf "  %s%s%s\n" "${D}" "----------------------------------------------------------------------------" "${NC}"; }
log_header() { echo -e "\n${LM}${SYM_SCAN}  $1 ${NC}"; draw_sep; }

draw_traffic_light() {
    local score=$1
    local r_char="!"; local y_char="!"; local g_char="!"
    local r_clr="${D}"; local y_clr="${D}"; local g_clr="${D}"
    local msg=""

    if [[ $score -ge 600 ]]; then
        r_clr="${LR}"; r_char="!"; msg="${LR}MALICIOUS${NC}"
    elif [[ $score -ge 200 ]]; then
        y_clr="${LY}"; y_char="!"; msg="${LY}SUSPICIOUS${NC}"
    else
        g_clr="${LG}"; g_char="!"; msg="${LG}CLEAN${NC}"
    fi

    echo -e "\n  ${BOLD}FINAL ASSESSMENT${NC}"
    echo -e "  ${D}+-------------------+${NC}"
    echo -e "  ${D}|${NC} ${r_clr}${r_char}${NC} ${D}|${NC}  ${D}Score :${NC} ${W}${score}${NC}"
    echo -e "  ${D}|${NC} ${y_clr}${y_char}${NC} ${D}|${NC}  ${D}State :${NC} ${msg}"
    echo -e "  ${D}|${NC} ${g_clr}${g_char}${NC} ${D}|${NC}"
    echo -e "  ${D}+-------------------+${NC}\n"
}

# --- Initialization ---
VERBOSE=false; LIST_MODE=false; IP_LIST=(); TARGET=""
RESULTS_FILE=$(mktemp)

show_help() {
    echo -e "${LC}${SYM_SCAN} IP-IR${NC}"
    echo -e "${D}Usage:${NC} $0 [options] <IP|Domain|URL|Hash|File>"
    echo -e ""
    echo -e "${LC}Options:${NC}"
    echo -e "  -v, --verbose    Expose raw API metrics & debugging"
    echo -e "  -l <file>        Batch process IPs from a file (Ultra-Parallel)"
    echo -e "  -h, --help       Show this interface"
    echo -e ""
    exit 0
}

# Check for File Hash
check_hash() {
    local input=$1
    local hashtype=""
    if [[ $input =~ ^[0-9a-fA-F]{32}$ ]]; then hashtype="md5"
    elif [[ $input =~ ^[0-9a-fA-F]{40}$ ]]; then hashtype="SHA1"
    elif [[ $input =~ ^[0-9a-fA-F]{64}$ ]]; then hashtype="SHA256"; fi

    if [[ -n "$hashtype" ]]; then
        echo -e "${LM}${SYM_FILE} Hash Detected: ${W}${input}${NC} (${hashtype})"
        if [[ -f "/Tools/mal.sh" ]]; then
            /usr/bin/bash /Tools/mal.sh "$input"
        else
            echo -e "${LR}${SYM_ERR} mal.sh not found. VT Lookup:${NC}"
            curl -s -H "x-apikey: $vtapi" "https://www.virustotal.com/api/v3/files/$input" | jq -r '.data.attributes.last_analysis_stats'
        fi
        exit 0
    fi
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE=true ;;
        -l) LIST_MODE=true; shift; [[ -f "$1" ]] && mapfile -t IP_LIST < <(grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" "$1" | sort -u) || { echo "File not found"; exit 1; } ;;
        -h|--help) show_help ;;
        *) [[ -z "$TARGET" ]] && TARGET="$1" ;;
    esac
    shift
done

[[ -z "$TARGET" && "$LIST_MODE" == false ]] && show_help
[[ -n "$TARGET" ]] && check_hash "$TARGET"

# --- Core Investigation Logic ---
investigate_ip() {
    local target_input=$1
    local ip=""
    local ioctype=""

    if [[ $target_input =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        ip=$target_input; ioctype="ipv4"
    elif [[ $target_input =~ ^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$ || $target_input =~ "::" ]]; then
        ip=$target_input; ioctype="ipv6"
    else
        local domain
        domain=$(echo "$target_input" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|:.*$||')
        ip=$(dig +short A "${domain}" | head -n 1)
        [[ -z "$ip" ]] && { ip=$(dig +short AAAA "${domain}" | head -n 1); ioctype="ipv6"; } || ioctype="ipv4"
        [[ -z "$ip" ]] && return 1
    fi

    local score=0
    local is_vpn=false; local is_tor=false; local is_proxy=false; local is_datacenter=false; local is_mobile=false
    local country="N/A"; local asn="N/A"; local org="N/A"
    local fraud_score=0; local abuse_conf=0; local vt_mal=0; local kasp_zone="Unknown"
    local otx_pulses=0; local crowdsec_rep="safe"; local threatfox_conf=0; local hybrid_matches=0

    local ipinfo_res
    ipinfo_res=$(curl -s --max-time 10 "https://ipinfo.io/$ip?token=$ipinfoapi")
    country=$(echo "$ipinfo_res" | jq -r '.country // "N/A"')
    asn=$(echo "$ipinfo_res" | jq -r '.org // "N/A"')
    org=$(whois "$ip" | grep -iE "OrgName|org-name|organisation|netname" | head -n 1 | awk -F: '{print $2}' | sed 's/^[ \t]*//')

    local ipq_res
    ipq_res=$(curl -s --max-time 10 "https://ipqualityscore.com/api/json/ip/$ipqapi/$ip?strictness=1&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=true")
    [[ $(echo "$ipq_res" | jq -r '.active_vpn // false') == "true" ]] && is_vpn=true
    [[ $(echo "$ipq_res" | jq -r '.active_tor // false') == "true" ]] && is_tor=true
    [[ $(echo "$ipq_res" | jq -r '.proxy // false') == "true" ]] && is_proxy=true
    [[ $(echo "$ipq_res" | jq -r '.mobile // false') == "true" ]] && is_mobile=true
    fraud_score=$(echo "$ipq_res" | jq -r '.fraud_score // 0')
    ((score += fraud_score))

    local pc_res
    pc_res=$(curl -s --max-time 10 "https://proxycheck.io/v2/$ip?vpn=1&asn=1")
    [[ $(echo "$pc_res" | jq -r --arg ip "$ip" '.[$ip].proxy // "no"') == "yes" ]] && is_proxy=true
    [[ $(echo "$pc_res" | jq -r --arg ip "$ip" '.[$ip].type // ""') == "VPN" ]] && is_vpn=true

    local ipis_res
    ipis_res=$(curl -s --max-time 10 "https://api.ipapi.is/?ip=$ip&key=$ipapisisapi")
    [[ $(echo "$ipis_res" | jq -r '.is_vpn // false') == "true" ]] && is_vpn=true
    [[ $(echo "$ipis_res" | jq -r '.is_datacenter // false') == "true" ]] && is_datacenter=true

    local abuse_res
    abuse_res=$(curl -s --max-time 10 -G https://api.abuseipdb.com/api/v2/check --data-urlencode ipAddress="$ip" -H "Key: $abuseapi" -H "Accept: application/json")
    abuse_conf=$(echo "$abuse_res" | jq -r '.data.abuseConfidenceScore // 0')
    ((score += abuse_conf * 4))

    local vt_res
    vt_res=$(curl -s --max-time 10 -H "x-apikey: $vtapi" "https://www.virustotal.com/api/v3/ip_addresses/$ip")
    vt_mal=$(echo "$vt_res" | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
    ((score += vt_mal * 150))

    otx_pulses=$(curl -s --max-time 10 -H "X-OTX-API-KEY: $otxapi" "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip" | jq -r '.pulse_info.count // 0')
    ((score += otx_pulses * 50))

    kasp_zone=$(curl -s --max-time 10 -H "x-api-key: $kasperskyapi" "https://opentip.kaspersky.com/api/v1/search/ip?request=$ip" | jq -r '.Zone // "Unknown"')
    [[ "$kasp_zone" == "Red" ]] && ((score += 500))
    [[ "$kasp_zone" == "Orange" ]] && ((score += 200))

    crowdsec_rep=$(curl -s --max-time 10 -H "x-api-key: $crowdsecapi" "https://cti.api.crowdsec.net/v2/smoke/$ip" | jq -r '.reputation // "safe"')
    [[ "$crowdsec_rep" == "malicious" ]] && ((score += 400))

    threatfox_conf=$(curl -s --max-time 10 -X POST https://threatfox-api.abuse.ch/api/v1/ -d "{ \"query\": \"search_ioc\", \"search_term\": \"$ip\" }" | jq -r '.data[0].confidence_level // 0')
    ((score += threatfox_conf * 3))

    hybrid_matches=$(curl -s --max-time 10 -H "api-key: $hybridapi" -H "accept: application/json" -d "host=$ip" "https://www.hybrid-analysis.com/api/v2/search/terms" | jq -r '.count // 0')
    ((score += hybrid_matches * 100))

    local urlhaus_hit
    urlhaus_hit=$(curl -s --max-time 5 https://urlhaus.abuse.ch/downloads/csv_online/ | grep -q "$ip" && echo "true" || echo "false")
    [[ "$urlhaus_hit" == "true" ]] && ((score += 400))

    local shodan_res
    shodan_res=$(curl -s --max-time 10 "https://api.shodan.io/shodan/host/$ip?key=$shdapi")
    local sh_tags
    sh_tags=$(echo "$shodan_res" | jq -r '.tags // [] | join(",")')
    [[ "$sh_tags" == *"vpn"* ]] && is_vpn=true
    [[ "$sh_tags" == *"tor"* ]] && is_tor=true

    local is_ms
    is_ms=$(curl -s --max-time 5 "https://www.azurespeed.com/api/ipAddress?ipOrDomain=$ip" | jq '. | length')
    [[ $is_ms -gt 0 ]] && ((score -= 300))

    local bl_count=0
    local bl_urls=("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt" "https://www.binarydefense.com/banlist.txt")
    for url in "${bl_urls[@]}"; do
        if curl -s --max-time 3 "$url" | grep -q "$ip"; then ((bl_count++)); fi
    done
    ((score += bl_count * 500))

    if [[ "$LIST_MODE" == false ]]; then
        echo -e "\n${LC}${SYM_INFO} Investigation: ${W}${ip}${NC} ${D}[${ioctype}]${NC}"
        log_stat "${SYM_LOC} Geolocation" "${LB}${country}${NC} | ${D}${asn}${NC}"
        log_stat "${SYM_NET} Organization" "${W}${org:-N/A}${NC}"

        local infra_str=""
        [[ "$is_vpn" == "true" ]] && infra_str+="${LY}${SYM_VPN} VPN ${NC}"
        [[ "$is_proxy" == "true" ]] && infra_str+="${LM}${SYM_PROXY} PROXY ${NC}"
        [[ "$is_tor" == "true" ]] && infra_str+="${LR}${SYM_TOR} TOR ${NC}"
        [[ "$is_datacenter" == "true" ]] && infra_str+="${LB}${SYM_DC} DC ${NC}"
        [[ "$is_mobile" == "true" ]] && infra_str+="${LC}${SYM_MOB} MOB ${NC}"
        [[ $is_ms -gt 0 ]] && infra_str+="${LG}${SYM_SHIELD} AZURE ${NC}"
        [[ -z "$infra_str" ]] && infra_str="${G}${SYM_OK} Resi/Unknown${NC}"
        log_stat "${SYM_SHIELD} Infrastructure" "$infra_str"

        local threat_str=""
        [[ $fraud_score -gt 50 ]] && threat_str+="${LR}Fraud:${fraud_score} ${NC}"
        [[ $abuse_conf -gt 20 ]] && threat_str+="${LR}Abuse:${abuse_conf}% ${NC}"
        [[ $vt_mal -gt 0 ]] && threat_str+="${LR}VT:${vt_mal} ${NC}"
        [[ $otx_pulses -gt 0 ]] && threat_str+="${LY}OTX:${otx_pulses} ${NC}"
        [[ "$crowdsec_rep" != "safe" ]] && threat_str+="${LR}CrowdSec:${crowdsec_rep} ${NC}"
        [[ $threatfox_conf -gt 0 ]] && threat_str+="${LR}ThreatFox:${threatfox_conf} ${NC}"
        [[ $hybrid_matches -gt 0 ]] && threat_str+="${LR}Hybrid:${hybrid_matches} ${NC}"
        [[ "$kasp_zone" != "Unknown" && "$kasp_zone" != "Green" ]] && threat_str+="${LR}Kasp:${kasp_zone} ${NC}"
        [[ $bl_count -gt 0 ]] && threat_str+="${LR}Blacklisted:${bl_count} ${NC}"
        [[ -z "$threat_str" ]] && threat_str="${G}${SYM_OK} No Major Hits${NC}"
        log_stat "${SYM_ERR} Threat Intel" "$threat_str"

        local hostnames
        hostnames=$(echo "$shodan_res" | jq -r '.hostnames // [] | join(", ")')
        [[ -z "$hostnames" ]] && command -v dnsx &> /dev/null && hostnames=$(dnsx -silent -resp-only -ptr "$ip")
        [[ -n "$hostnames" ]] && log_stat "${SYM_WEB} Hostnames" "${LC}${hostnames}${NC}"

        draw_traffic_light "$score"

        if [[ $score -ge 1200 && $abuse_conf -gt 50 ]]; then
            log_verbose "Reporting $ip to AbuseIPDB..."
            curl -s -o /dev/null "https://api.abuseipdb.com/api/v2/report" --data-urlencode ip="$ip" -d categories=15 --data-urlencode "comment=Sentinel Prime Report: High risk score ($score)" -H "Key: $abuseapi" -H "Accept: application/json"
        fi
    fi

    echo "$score|$ip|$country|$is_vpn|$is_proxy|$is_tor|$is_mobile|$is_datacenter|$asn" >> "$RESULTS_FILE"
}

# --- Main Logic ---
echo -e "${LM}$(cat << "EOF"
██╗██████╗     ██╗██████╗ 
██║██╔══██╗    ██║██╔══██╗
██║██████╔╝    ██║██████╔╝
██║██╔═══╝     ██║██╔══██╗
██║██║         ██║██║  ██║
╚═╝╚═╝         ╚═╝╚═╝  ╚═╝
╔══════════════════════════════╗
║                              ║
║ IP-based   Incident Response ║
║                              ║
╚══════════════════════════════╝
EOF
)${NC}  ${D}Author: Patrick Binder${NC}"

if [[ "$LIST_MODE" == true ]]; then
    log_header "Ultra-Parallel Batch Analysis: ${#IP_LIST[@]} Targets"
    for ip_entry in "${IP_LIST[@]}"; do
        investigate_ip "$ip_entry" > /dev/null &
    done

    echo -ne "  ${D}Crunching data... ${NC}"
    while [[ $(jobs -r | wc -l) -gt 0 ]]; do
        echo -ne "${LC}${SYM_TIME} ${NC}"
        sleep 0.5
    done
    echo -e "${LG}${SYM_OK} Complete${NC}"

    log_header "Risk Assessment Matrix (Sorted by Risk Index)"
    mapfile -t sorted_results < <(sort -rn -t'|' -k1 "$RESULTS_FILE")

    printf "  ${BOLD}%-6s %-16s %-4s %-10s %-15s${NC}\n" "Score" "IP Address" "LOC" "Infra" "Provider Status"
    draw_sep
    for line in "${sorted_results[@]}"; do
        (
            IFS='|' read -r r_score r_ip r_loc r_vpn r_proxy r_tor r_mobile r_dc r_asn <<< "$line"
            r_clr="${LG}"; [[ $r_score -ge 200 ]] && r_clr="${LY}"; [[ $r_score -ge 600 ]] && r_clr="${LR}"
            r_infra=""; [[ "$r_vpn" == "true" ]] && r_infra+="V"; [[ "$r_proxy" == "true" ]] && r_infra+="P"; [[ "$r_tor" == "true" ]] && r_infra+="T"; [[ "$r_mobile" == "true" ]] && r_infra+="m"; [[ "$r_dc" == "true" ]] && r_infra+="D"; [[ -z "$r_infra" ]] && r_infra="-"
            r_status="CLEAN"; [[ $r_score -ge 200 ]] && r_status="SUSP"; [[ $r_score -ge 600 ]] && r_status="MALIC"
            r_asn_short=$(echo "$r_asn" | cut -c 1-15)
            printf "  ${r_clr}%-6d %-16s %-4s %-10s %-15s${NC}\n" "$r_score" "$r_ip" "$r_loc" "$r_infra" "$r_asn_short ($r_status)"
        )
    done
else
    investigate_ip "$TARGET"
fi

rm -f "$RESULTS_FILE"
echo -e "\n${D}${SYM_SCAN} Audit completed successfully.${NC}"
