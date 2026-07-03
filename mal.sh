#!/bin/bash
## Script for Malware
## Author Patrick Binder
## Date Q1/2023
## Starting Point
## Api-Keys
##
source /root/Tools/apikeys.txt
datetime=$(date '+%d.%m.%Y %H:%M:%S UHR')
## -------------------------------------------------------------------------------------------------------
## init var
score=0
## init json
## wenn argument für webhook + Logic apps ==  stdout wird nicht ausgegeben nur am ende die JSON mit den Ergebnissen. stderror geht an /var/log/irsh.log
## ___________________________________________Chapter 1 INCIDENT RESPONSE________________________________
##Che
#
hash=$1
if [[ $hash =~ ^[0-9a-fA-F]{32}$ ]]; then
hashtype=md5
# Check if input is a valid SHA1 value
elif [[ $hash =~ ^[0-9a-fA-F]{40}$ ]]; then
 hashtype=SHA1
elif [[ $hash =~ ^[0-9a-fA-F]{64}$ ]]; then
 hashtype=SHA256
fi
echo "Investigation is starting for ...."
echo -e "Investigation will start for:\033[0;1;32m "Hashtype=${hashtype} -- Hashvalue ${hash}"\033[0m"
echo -e "starting time \033[0;1;32m${datetime}\033[0m"
start_time=$(date +%s)
echo -e ""
echo -e ""
echo 
#### -----------------------------------START TI---------------------------------------------------------------------

echo -n -e "\033[1;33m--------------------------  Threat Intelligence --------------------\e[0m"
echo -e "\033[30;47mRiskScore= "$score" \e[0m"
echo -e ""
echo -e ""
## -----------------------------------VT Check Hash---------------------------------------------------------------------
vt_response=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/files/$hash" \
  --header "x-apikey: ${vtapi2}")

# Extract fields from the VT file report
vtpositives=$(echo "$vt_response" | jq -r '.data.attributes.last_analysis_stats.malicious')
vtsuspicious=$(echo "$vt_response" | jq -r '.data.attributes.last_analysis_stats.suspicious')
vtreputation=$(echo "$vt_response" | jq -r '.data.attributes.reputation')
vtlabel=$(echo "$vt_response" | jq -r '.data.attributes.popular_threat_classification.suggested_threat_label')
vtfilename0=$(echo "$vt_response" | jq -r '.data.attributes.names[0]')
vtfilename1=$(echo "$vt_response" | jq -r '.data.attributes.names[1]')
vtfilename2=$(echo "$vt_response" | jq -r '.data.attributes.names[2]')
vtsignatureinfo=$(echo "$vt_response" | jq -r '.data.attributes.signature_info')


# Check VT file results and update risk score
if echo "$vt_response" | jq -e '.data' >/dev/null 2>&1; then

# Generate the VirusTotal clickable link
    vt_link="https://www.virustotal.com/gui/file/$hash"
    vt_clickable="\033]8;;$vt_link\033\\VirusTotal Link\033]8;;\033\\"
    
    # Check VT file results and update risk score
    if [ "$vtpositives" -eq 0 ] && [ "$vtsuspicious" -eq 0 ]; then
        echo -n -e "\033[0;32mNo detections from VirusTotal. Reputation: $vtreputation\033[0m"
        score=$((score + 0))
    elif [ "$vtpositives" -gt 0 ] && [ "$vtpositives" -le 3 ]; then
        echo -e "\033[0;33mVirusTotal has $vtpositives positives (suspicious). Reputation: $vtreputation --> $vt_clickable"
        echo -e "      📂 Filenames: \033[1;36m$vtfilename0, $vtfilename1, $vtfilename2\033[0m"
        echo -e "      🚨 Threat Label: \033[1;36m$vtlabel\033[0m"
        score=$((score + 200))
    elif [ "$vtpositives" -gt 3 ] && [ "$vtpositives" -lt 7 ]; then
        echo -e "\033[0;31m⚠️ ATTENTION: VirusTotal has $vtpositives positives (malicious). Reputation: $vtreputation --> $vt_clickable"
        echo -e "      📂 Filenames: \033[1;36m$vtfilename0, $vtfilename1, $vtfilename2\033[0m"
        echo -e "      🚨 Threat Label: \033[1;36m$vtlabel\033[0m"
        score=$((score + 500))
    elif [ "$vtpositives" -ge 7 ] && [ "$vtpositives" -lt 15 ]; then
        echo -e "\033[0;31m🔥 ATTENTION: VirusTotal has $vtpositives positives (very MALICIOUS). Reputation: $vtreputation --> $vt_clickable"
        echo -e "      📂 Filenames: \033[1;36m$vtfilename0, $vtfilename1, $vtfilename2\033[0m"
        echo -e "      🚨 Threat Label: \033[1;36m$vtlabel\033[0m"
        score=$((score + 700))
    elif [ "$vtpositives" -ge 15 ]; then
        echo -e "\033[0;31m🚨🚨🚨 ATTENTION: VirusTotal has $vtpositives positives (SUPER MALICIOUS). Reputation: $vtreputation --> $vt_clickable"
        echo -e "      📂 Filenames: \033[1;36m$vtfilename0, $vtfilename1, $vtfilename2\033[0m"
        echo -e "      🚨 Threat Label: \033[1;36m$vtlabel\033[0m"
        score=$((score + 1100))
    elif [ "$vtsuspicious" -gt 0 ]; then
        echo -e "\033[0;31m⚠️ ATTENTION: VirusTotal shows $vtsuspicious suspicious detections. Reputation: $vtreputation --> $vt_clickable"
        echo -e "      📂 Filenames: \033[1;36m$vtfilename0, $vtfilename1, $vtfilename2\033[0m"
        echo -e "      🚨 Threat Label: \033[1;36m$vtlabel\033[0m"
        score=$((score + 50))
    fi


################### VirusTotal Contacted IPs (first 10) ###################
vt_ips_response=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/files/$hash/contacted_ips" \
  --header "x-apikey: ${vtapi2}")

num_ips=$(echo "$vt_ips_response" | jq '.data | length')
if [ "$num_ips" -gt 0 ]; then
    echo -e "\n\033[1;33mVirusTotal Contacted IP Addresses (first 10):\033[0m"
    total_ip_mal=0
    for (( i=0; i < num_ips && i < 10; i++ )); do
       ip=$(echo "$vt_ips_response" | jq -r ".data[$i].id")
       ip_mal=$(echo "$vt_ips_response" | jq -r ".data[$i].attributes.last_analysis_stats.malicious")
       echo "  IP: $ip with $ip_mal positives"
       total_ip_mal=$(( total_ip_mal + ip_mal ))
       vt_ip_link="https://www.virustotal.com/gui/ip-address/${ip}/detection"
       vt_ip_clickable="\033]8;;$vt_ip_link\033\\VT IP Report\033]8;;\033\\"
       echo -e "    Link: $vt_ip_clickable"
    done

    if [ "$total_ip_mal" -le 5 ]; then
         echo -n -e "\033[0;33mTotal positives across contacted IPs: $total_ip_mal (suspicious)\033[0m"
         score=$((score + 0))
    elif [ "$total_ip_mal" -ge 6 ] && [ "$total_ip_mal" -le 15 ]; then
         echo -n -e "\033[0;31mTotal positives across contacted IPs: $total_ip_mal (malicious)\033[0m"
         score=$((score + 300))
    elif [ "$total_ip_mal" -ge 16 ]; then
         echo -n -e "\033[0;31mTotal positives across contacted IPs: $total_ip_mal (SUPER MALICIOUS)\033[0m"
         score=$((score + 600))
    fi
else
    echo -n -e "\nNo contacted IP addresses related to this hash were found."
    score=$((score + 0))
fi

################### VirusTotal Contacted URLs (first 10) ###################
    vt_urls_response=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/files/$hash/contacted_urls" \
      --header "x-apikey: ${vtapi2}")
    
    num_urls=$(echo "$vt_urls_response" | jq '.data | length')
    if [ "$num_urls" -gt 0 ]; then
        echo -e "\n\033[1;33mVirusTotal Contacted URLs (first 10):\033[0m"
        total_url_mal=0
        for (( i=0; i < num_urls && i < 10; i++ )); do
           url_id=$(echo "$vt_urls_response" | jq -r ".data[$i].id")
           final_url=$(echo "$vt_urls_response" | jq -r ".data[$i].attributes.last_final_url")
           url_mal=$(echo "$vt_urls_response" | jq -r ".data[$i].attributes.last_analysis_stats.malicious")
           echo "  URL: $final_url with $url_mal positives"
           total_url_mal=$(( total_url_mal + url_mal ))
           vt_url_link="https://www.virustotal.com/gui/url/${url_id}/detection"
           vt_url_clickable="\033]8;;$vt_url_link\033\\VT URL Report\033]8;;\033\\"
           echo -e "    Link: $vt_url_clickable"
        done
    
        if [ "$total_url_mal" -le 5 ]; then
             echo -n -e "\033[0;33mTotal positives across contacted URLs: $total_url_mal (suspicious)\033[0m"
             score=$((score + 0))
        elif [ "$total_url_mal" -ge 6 ] && [ "$total_url_mal" -le 15 ]; then
             echo -n -e "\033[0;31mTotal positives across contacted URLs: $total_url_mal (malicious)\033[0m"
             score=$((score + 300))
        elif [ "$total_url_mal" -ge 16 ]; then
             echo -n -e "\033[0;31mTotal positives across contacted URLs: $total_url_mal (SUPER MALICIOUS)\033[0m"
             score=$((score + 600))
        fi
    else
        echo -e "\nNo contacted URLs related to this hash were found."
        score=$((score + 0))
    fi

else
    echo -e "\033[0;32mNo Results from Virus Total.\033[0m"
fi


## ---------------------------- Intezer Analysis ----------------------------

# Generate the Intezer clickable link
intezer_link="https://analyze.intezer.com/#/files/$hash"
intezer_clickable="\033]8;;$intezer_link\033\\Intezer Report\033]8;;\033\\"

# Get Intezer access token
intezertoken=$(curl -s --request POST --url https://analyze.intezer.com/api/v2-0/get-access-token \
  --header 'Content-Type: application/json' \
  --data '{"api_key": "'"${intezerapi}"'"}' | jq -r '.result')

# Query Intezer for hash analysis
intezerresult=$(curl -s --request GET --url "https://analyze.intezer.com/api/v2-0/files/$hash" \
  --header "Authorization: Bearer ${intezertoken}" \
  --header "Content-Type: application/json")

# Check for an error in the response (e.g., "Analysis was not found")
intezererror=$(echo "$intezerresult" | jq -r '.error // empty')

if [ -n "$intezererror" ]; then
    echo -e "\033[0;32mNo Results from Intezer.\e[0m"
    score=$((score + 0))
else
    intezermal=$(echo "$intezerresult" | jq -r '.result.verdict')

    if [[ $intezermal == "malicious" ]]; then
        echo -e "\033[0;31m🚨 Intezer found an indicator which is malicious! --> $intezer_clickable"
        echo -e "      🧬 Verdict: \033[1;36m$intezermal\033[0m"
        score=$((score + 250))
    else
        echo -e "\033[0;32mNo malicious verdict from Intezer.\e[0m"
        score=$((score + 0))
    fi
fi


## ---------------------------- Bazaar Abuse Analysis ----------------------------

# Generate the Bazaar Abuse clickable link
bazaar_link="https://bazaar.abuse.ch/sample/${hash}"
bazaar_clickable="\033]8;;$bazaar_link\033\\Bazaar Abuse Report\033]8;;\033\\"

# Query Bazaar Abuse for hash analysis
bazaarstatus=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d 'query=get_info&hash='$hash'' | jq -r '.query_status')

if [[ $bazaarstatus == "ok" ]]; then
    echo -e "\033[0;31m🚨 Bazaar Abuse found an indicator which is malicious! --> $bazaar_clickable"
    score=$((score + 250))
else
    echo -e "\033[0;32mNo Results from Bazaar.Abuse.ch.\e[0m"
    score=$((score + 0))
fi


## ---------------------------- AlienVault OTX Analysis ----------------------------

# Generate the AlienVault OTX clickable link
otx_link="https://otx.alienvault.com/indicator/file/$hash"
otx_clickable="\033]8;;$otx_link\033\\AlienVault OTX Report\033]8;;\033\\"

# Query AlienVault OTX for hash analysis
pulsecount=$(curl -s -X GET --url "https://otx.alienvault.com/api/v1/indicators/file/$hash" \
  -H "X-OTX-API-KEY: ${otxapi}" | jq '.pulse_info | .count')

# Process results
if [ "$pulsecount" -gt 0 ] && [ "$pulsecount" -le 2 ]; then
    echo -e "\033[0;33m⚠️ AlienVault OTX found $pulsecount Pulses (Suspicious) --> $otx_clickable"
    score=$((score + 100))
elif [ "$pulsecount" -gt 2 ] && [ "$pulsecount" -le 15 ]; then
    echo -e "\033[0;31m🚨 AlienVault OTX found $pulsecount Pulses (Malicious) --> $otx_clickable"
    score=$((score + 250))
elif [ "$pulsecount" -gt 15 ]; then
    echo -e "\033[0;31m🔥 AlienVault OTX found $pulsecount Pulses (VERY MALICIOUS) --> $otx_clickable"
    score=$((score + 400))
else
    echo -e "\033[0;32mNo Results from AlienVault OTX Pulses.\e[0m"
    score=$((score + 0))
fi


## ---------------------------- OPSWAT MetaDefender Analysis ----------------------------

# Generate the OPSWAT clickable link
opswat_link="https://metadefender.opswat.com/results/file/${hash}/hash/multiscan"
opswat_clickable="\033]8;;$opswat_link\033\\OPSWAT MetaDefender Report\033]8;;\033\\"

# Query OPSWAT MetaDefender for hash analysis
opswatdetect=$(curl -s --request GET --url "https://api.metadefender.com/v4/hash/$hash" \
  --header "apikey: ${opswatapi}" | jq '.scan_results | .total_detected_avs')

opswatlines=$(curl -s --request GET --url "https://api.metadefender.com/v4/hash/$hash" \
  --header "apikey: ${opswatapi}" | jq | wc -l)

# Process results
if [ "$opswatlines" -gt 8 ]; then
    if [ "$opswatdetect" -gt 0 ] && [ "$opswatdetect" -le 2 ]; then
        echo -e "\033[0;33m⚠️ OPSWAT detected $opswatdetect positives (Suspicious) --> $opswat_clickable"
        score=$((score + 150))
    elif [ "$opswatdetect" -gt 2 ]; then
        echo -e "\033[0;31m🚨 OPSWAT detected $opswatdetect positives (Malicious) --> $opswat_clickable"
        score=$((score + 350))
    else
        echo -e "\033[0;32mNo detections from OPSWAT MetaDefender.\e[0m"
        score=$((score + 0))
    fi
else
    echo -e "\033[0;32mNo results found on OPSWAT MetaDefender.\e[0m"
    score=$((score + 0))
fi

## ---------------------------- Kaspersky OpenTIP Analysis ----------------------------

# Generate the Kaspersky clickable link
kaspersky_link="https://opentip.kaspersky.com/${hash}/?tab=lookup"
kaspersky_clickable="\033]8;;$kaspersky_link\033\\Kaspersky OpenTIP Report\033]8;;\033\\"

# Query Kaspersky OpenTIP API for hash analysis
kaspzone=$(curl -s --request GET --url "https://opentip.kaspersky.com/api/v1/search/hash?request=${hash}" \
  --header "x-api-key: ${kasperskyapi}" | jq -r '.Zone')

# Process results
if [ -n "$kaspzone" ]; then
    if [ "$kaspzone" == "Red" ]; then
        echo -e "\033[0;31m🚨 Kaspersky tags this hash as MALICIOUS --> $kaspersky_clickable"
        score=$((score + 350))
    elif [ "$kaspzone" == "Orange" ]; then
        echo -e "\033[0;33m⚠️ Kaspersky tags this hash as SUSPICIOUS --> $kaspersky_clickable"
        score=$((score + 100))
    else
        echo -e "\033[0;32mNo detections from Kaspersky OpenTIP.\e[0m"
        score=$((score + 0))
    fi
else
    echo -e "\033[0;32mNo results found on Kaspersky OpenTIP.\e[0m"
    score=$((score + 0))
fi

## ---------------------------- Hybrid Analysis Report ----------------------------

# Generate the Hybrid Analysis clickable link
hybrid_link="https://www.hybrid-analysis.com/search?query=${hash}"
hybrid_clickable="\033]8;;$hybrid_link\033\\Hybrid Analysis Report\033]8;;\033\\"

# Query Hybrid Analysis API for hash analysis
hybrid_response=$(curl -s --request GET --url "https://www.hybrid-analysis.com/api/v2/overview/$hash/summary" \
  -H 'accept: application/json' \
  -H 'user-agent: Falcon Sandbox' \
  -H "api-key: $hybridapi" \
  -H 'Content-Type: application/x-www-form-urlencoded')

# Extract analysis result
hybridresult=$(echo "$hybrid_response" | jq -r '.multiscan_result')
hybridlines=$(echo "$hybrid_response" | jq | wc -l)

# Process results
if [ "$hybridlines" -gt 3 ]; then
    if [ "$hybridresult" -gt 0 ] && [ "$hybridresult" -le 49 ]; then
        echo -e "\033[0;33m⚠️ Hybrid Analysis detected a malicious probability of ${hybridresult}% --> $hybrid_clickable"
        score=$((score + 150))
    elif [ "$hybridresult" -gt 49 ]; then
        echo -e "\033[0;31m🚨 Hybrid Analysis detected a HIGH malicious probability of ${hybridresult}%! --> $hybrid_clickable"
        score=$((score + 350))
    else
        echo -e "\033[0;32mNo detections from Hybrid Analysis.\e[0m"
        score=$((score + 0))
    fi
else
    echo -e "\033[0;32mNo results found in Hybrid Analysis.\e[0m"
    score=$((score + 0))
fi

## --------------------------- FINAL SUMMARY ---------------------------
echo -n -e "\033[1;33m------------------------------ SUMMARY ----------------------\e[0m"
echo -e "\033[30;47m  Risk Score: $score  \e[0m"
echo ""
echo ""

# Categorize and colorize RiskScore
if [[ $score -ge -10000 && $score -le 99 ]]; then
        echo -e "\033[1;32m ✅ RISK Score = $score  (Low Risk) \033[0m";
elif [[ $score -ge 100 && $score -lt 500 ]]; then
        echo -e "\033[1;4;33m ⚠️  RISK Score = $score  (Moderate Risk) \033[0m";
else
        echo -e "\033[1;5;31m   --------------------------------------------------\033[0m";
        echo -e "\033[1;31m     🚨🚨🚨    >>>  HIGH RISK SCORE = $score  <<<    🚨🚨🚨 \033[0m";
        echo -e "\033[1;5;31m   --------------------------------------------------\033[0m";
fi

# Additional threat context markers
echo ""
if [[ $isvpn == true ]]; then
        echo -e "\033[1;34m 🔹 VPN Detected: $isvpn \033[0m";
fi
if [[ $istor == true ]]; then
        echo -e "\033[1;35m 🔹 TOR Exit Node Detected: $istor \033[0m";
fi
if [[ $isriot == true ]]; then
        echo -e "\033[1;36m 🔹 GreyRiot Indicator: $isriot \033[0m";
fi
if [[ $isotxwhitelisted == true ]]; then
        echo -e "\033[1;33m 🔹 OTX Whitelisted: $isotxwhitelisted \033[0m";
fi
echo ""

end_time=$(date +%s)
runtime=$(( end_time - start_time ))
echo -e "\n\033[1;33mInvestigation completed successfully in ${runtime} seconds.\033[0m"
exit 0
