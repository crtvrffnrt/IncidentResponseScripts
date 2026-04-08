#!/bin/bash
## Author Patrick Binder
## This script runs a script on all excistent ARC Hosts
# --- CONFIGURATION ---
SCRIPT_PATH="./checkifcompromised.ps1"
RUN_NAME="GlobalCompromiseAudit-$(date +%s)"

# 1. Validate environment
if [ ! -f "$SCRIPT_PATH" ]; then
    echo "Error: Assessment script not found at $SCRIPT_PATH"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' is not installed. Please run: sudo apt install jq"
    exit 1
fi

# 2. Escape the PowerShell script content once for JSON
echo "[i] Preparing script for transport..."
ESCAPED_SCRIPT=$(cat "$SCRIPT_PATH" | python3 -c 'import json, sys; print(json.dumps(sys.stdin.read()))')

# 3. Fetch all Arc-enabled machines across all resource groups
echo "[i] Fetching list of all Azure Arc machines..."
MACHINES=$(az connectedmachine list --query "[].{id:id, name:name, location:location}" -o json)

COUNT=$(echo "$MACHINES" | jq '. | length')
echo "[+] Found $COUNT Arc machines."

# 4. Iterate and execute
echo "$MACHINES" | jq -c '.[]' | while read -r machine; do
    NAME=$(echo "$machine" | jq -r '.name')
    ID=$(echo "$machine" | jq -r '.id')
    LOC=$(echo "$machine" | jq -r '.location')

    echo "----------------------------------------------------------------------"
    echo "[*] TARGET: $NAME | LOCATION: $LOC"

    # Trigger the Run Command using the machine's specific location
    az rest --method put \
      --uri "https://management.azure.com${ID}/runCommands/${RUN_NAME}?api-version=2024-03-31-preview" \
      --body "{
        \"location\": \"$LOC\",
        \"properties\": {
          \"source\": {
            \"script\": $ESCAPED_SCRIPT
          }
        }
      }" --output none

    if [ $? -eq 0 ]; then
        echo " [+] Request accepted. Script is now queuing on the agent."
    else
        echo " [!] Failed to trigger on $NAME. Check permissions or agent status."
    fi
done

echo "----------------------------------------------------------------------"
echo "[DONE] Assessment triggered on all reachable machines."
echo "[i] Monitor the 'ir-results' container in your storage account 'hsvirresults7051'."
