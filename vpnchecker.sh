#!/usr/bin/env bash

set -euo pipefail

# Load API keys
source /root/Tools/apikeys.txt

API_URL="https://api.ipapi.is"

usage() {
  printf "Usage: %s -i <ips.txt>\n" "$(basename "$0")"
  exit 1
}

ips_file=""
while getopts ":i:h" opt; do
  case "$opt" in
    i) ips_file="$OPTARG" ;;
    h|*) usage ;;
  esac
done

if [[ -z "$ips_file" ]]; then
  ips_file="ips.txt"
fi

if [[ ! -f "$ips_file" ]]; then
  printf "Error: input file not found: %s\n" "$ips_file" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  printf "Error: jq is required but not found in PATH\n" >&2
  exit 1
fi

if [[ -z "${ipapisisapi:-}" ]]; then
  printf "Error: API key 'ipapisisapi' not set (check /Tools/apikeys.txt)\n" >&2
  exit 1
fi

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
RESET="\033[0m"

printf "%b\n" "${BLUE}Incident Response: VPN Signal Check${RESET}"
printf "%-18s %-8s %-20s %-10s\n" "IP" "IsVPN" "VPNProvider" "Flag"
printf "%-18s %-8s %-20s %-10s\n" "--" "-----" "-----------" "----"

total=0
vpn_true=0
vpn_false=0
vpn_unknown=0

while IFS= read -r ip; do
  # Skip empty lines or comments
  [[ -z "$ip" || "$ip" =~ ^# ]] && continue

  total=$((total + 1))

  response=$(curl -s "${API_URL}/?ip=${ip}" \
    -H "Authorization: Bearer ${ipapisisapi}")

  is_vpn=$(echo "$response" | jq -r '.is_vpn // "unknown"')
  vpn_provider=$(echo "$response" | jq -r '.vpn.service // "N/A"')

  if [[ "$is_vpn" == "true" ]]; then
    flag="${RED}MALICIOUS${RESET}"
    color="${RED}"
    vpn_true=$((vpn_true + 1))
  elif [[ "$is_vpn" == "false" ]]; then
    flag="${GREEN}OK${RESET}"
    color="${GREEN}"
    vpn_false=$((vpn_false + 1))
  else
    flag="${YELLOW}UNKNOWN${RESET}"
    color="${YELLOW}"
    vpn_unknown=$((vpn_unknown + 1))
  fi

  printf "%b%-18s %-8s %-20s %-10b\n" "$color" "$ip" "$is_vpn" "$vpn_provider" "$flag"
done < "$ips_file"

printf "\n%bOverview${RESET}\n" "${BLUE}"
printf "Total IPs: %d\n" "$total"
printf "%bVPN (malicious): %d%b\n" "${RED}" "$vpn_true" "${RESET}"
printf "%bNot VPN: %d%b\n" "${GREEN}" "$vpn_false" "${RESET}"
printf "%bUnknown: %d%b\n" "${YELLOW}" "$vpn_unknown" "${RESET}"
