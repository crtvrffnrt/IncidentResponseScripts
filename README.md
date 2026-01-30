# Incident Response Scripts

A collection of small helpers for incident response workflows.

## 1. Graph Mail IR (`graph_mail_ir.py`)

Search for specific emails across Exchange Online mailboxes using Microsoft Graph.

### Setup

1.  **Prepare Message IDs**: Create a file (e.g., `message_ids.txt`) containing the Internet Message IDs you want to find (one per line).
2.  **Register App**: Run the helper script to create an Azure AD app with necessary permissions (`Mail.Read`, `User.Read.All`, `Directory.Read.All`).
    ```bash
    ./mailreadappcreate.sh
    ```
    *Note the Tenant ID, Client ID, and Client Secret from the output.*

### Usage

Execute the Python script using the credentials from the setup step:

```bash
python3 graph_mail_ir.py \
  --tenant-id <tenant-id> \
  --client-id <client-id> \
  --client-secret "<client-secret>" \
  --input message_ids.txt \
  --output mail_timeline1.csv \
  --upn '<optional-user-principal-name>'
```

*   `--upn`: Optional. Scopes search to a single mailbox (faster). Omit to search all users.
*   `--input`: Path to file containing Internet Message IDs.
*   `--output`: Path to CSV output file.

---

## 2. VPN Checker (`vpnchecker.sh`)

Checks a list of IPs for VPN indicators using **ipapi.is**.

### Setup & Requirements

1.  Install `jq` and `curl`.
2.  Set your API key in `/Tools/apikeys.txt`:
    ```bash
    export ipapisisapi="YOUR_API_KEY"
    ```
3.  Create an input file `ips.txt` (or specify another with `-i`).

### Usage

```bash
./vpnchecker.sh -i ips.txt
```

### Output

Flags IPs as **MALICIOUS** (VPN detected), **OK** (Not VPN), or **UNKNOWN**.