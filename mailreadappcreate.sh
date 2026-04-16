#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Graph-Mail-IR-Exporter"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
SECRET_DISPLAY_NAME="ir-export-secret"

MAIL_READ_ROLE="810c84a8-4a9e-49e6-bf7d-12d183f40d01"
USER_READ_ALL_ROLE="df021288-bdef-4463-88db-98f22de89214"
DIRECTORY_READ_ALL_ROLE="7ab1d382-f21e-4acd-a863-ba3e13f7da61"

print_help() {
  cat <<EOF
Usage:
  ./mailreadappcreate.sh [--app-name NAME] [--secret-name NAME]

Create a Microsoft Entra ID app registration for Graph Mail IR mailbox enrichment.

This helper is intended for incident response cases where a responder needs an
application identity to enrich Internet Message IDs from compromised or suspected
mailboxes with sender, recipient, folder, and timestamp data via Microsoft Graph.

What this script does:
  - Deletes an existing app registration with the same name, if present
  - Creates a new app registration and service principal
  - Adds Microsoft Graph application permissions:
      Mail.Read
      User.Read.All
      Directory.Read.All
  - Grants tenant-wide admin consent
  - Creates a client secret for non-interactive Graph access

Requirements:
  - Azure CLI ('az') installed
  - Signed in to the correct tenant before execution
  - Rights to create app registrations and grant admin consent
  - Use only in an authorized Microsoft 365 / Entra ID investigation

Flags:
  -h, --help              Show this help page and exit
  --app-name NAME        App registration display name
                         Default: Graph-Mail-IR-Exporter
  --secret-name NAME     Client secret display name
                         Default: ir-export-secret

Examples:
  ./mailreadappcreate.sh

  ./mailreadappcreate.sh --app-name Graph-Mail-IR-Exporter-Case123

  ./mailreadappcreate.sh \\
    --app-name Graph-Mail-IR-Exporter-UserA \\
    --secret-name ir-export-secret-2026-04

Next step:
  Use the returned Tenant ID, Client ID, and Client Secret with:
    python3 graph_mail_ir.py --help

Operational notes:
  - The client secret is shown once. Store it securely.
  - Re-running this script with the same app name deletes the existing app first.
  - The created app has tenant-wide read capability according to the granted Graph permissions.
EOF
}

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[!] Required command not found: $cmd" >&2
    exit 1
  fi
}

require_az_login() {
  if ! az account show >/dev/null 2>&1; then
    echo "[!] Azure CLI is not logged in or no active subscription / tenant context is selected." >&2
    echo "[!] Run 'az login' and verify the target tenant before executing this helper." >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      print_help
      exit 0
      ;;
    --app-name)
      [[ $# -ge 2 ]] || { echo "[!] Missing value for --app-name" >&2; exit 1; }
      APP_NAME="$2"
      shift 2
      ;;
    --secret-name)
      [[ $# -ge 2 ]] || { echo "[!] Missing value for --secret-name" >&2; exit 1; }
      SECRET_DISPLAY_NAME="$2"
      shift 2
      ;;
    *)
      echo "[!] Unknown argument: $1" >&2
      echo "[!] Use --help to see supported flags." >&2
      exit 1
      ;;
  esac
done

require_command az
require_az_login

# Cleanup existing app if it exists
echo "[*] Checking for existing app with name '$APP_NAME'"
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
  --display-name "$SECRET_DISPLAY_NAME" \
  --query password -o tsv)

TENANT_ID=$(az account show --query tenantId -o tsv)

echo
echo "==================== OUTPUT ===================="
echo "Tenant ID:        $TENANT_ID"
echo "Client ID:        $APP_ID"
echo "SP Object ID:     $SP_OBJECT_ID"
echo "Client Secret:    $CLIENT_SECRET"
echo "================================================"
