#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Graph-Mail-IR-Exporter"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"

MAIL_READ_ROLE="810c84a8-4a9e-49e6-bf7d-12d183f40d01"
USER_READ_ALL_ROLE="df021288-bdef-4463-88db-98f22de89214"
DIRECTORY_READ_ALL_ROLE="7ab1d382-f21e-4acd-a863-ba3e13f7da61"

# Cleanup existing app if it exists
echo "[*] Checking for existing app with name '$APP_NAME'வுகளை"
EXISTING_APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[].appId" -o tsv)
if [ -n "$EXISTING_APP_ID" ]; then
  echo "[-] Found existing app ($EXISTING_APP_ID). Deleting..."
  az ad app delete --id "$EXISTING_APP_ID"
  echo "[-] Deleted."
  sleep 5
fi

echo "[+] Creating App Registration..."
APP_ID=$(az ad app create \
  --display-name "$APP_NAME" \
  --sign-in-audience AzureADMyOrg \
  --query appId -o tsv)
echo "    > App ID: $APP_ID"

echo "[+] Creating Service Principal..."
SP_OBJECT_ID=$(az ad sp create \
  --id "$APP_ID" \
  --query id -o tsv)
echo "    > SP Object ID: $SP_OBJECT_ID"

echo "[*] Waiting 20s for propagation..."
sleep 20

echo "[+] Adding Microsoft Graph application permissions..."
az ad app permission add \
  --id "$APP_ID" \
  --api "$GRAPH_APP_ID" \
  --api-permissions \
    "$MAIL_READ_ROLE=Role" \
    "$USER_READ_ALL_ROLE=Role" \
    "$DIRECTORY_READ_ALL_ROLE=Role"

echo "[*] Waiting 10s for permission update propagation..."
sleep 10

echo "[+] Granting tenant-wide admin consent..."
az ad app permission admin-consent --id "$APP_ID"

echo "[+] Creating client secret..."
CLIENT_SECRET=$(az ad app credential reset \
  --id "$APP_ID" \
  --display-name "ir-export-secret" \
  --query password -o tsv)

TENANT_ID=$(az account show --query tenantId -o tsv)

echo
echo "==================== OUTPUT ===================="
echo "Tenant ID:        $TENANT_ID"
echo "Client ID:        $APP_ID"
echo "SP Object ID:     $SP_OBJECT_ID"
echo "Client Secret:    $CLIENT_SECRET"
echo "================================================"#    
