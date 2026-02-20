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

---

## 3. IP to Host (`iptohost.py`)

Finds distinct current and historical hostnames related to an IP address by querying multiple OSINT sources (Shodan, VirusTotal, Passive DNS, etc.).

### Setup & Requirements

1.  **Python 3** and **curl** must be installed.
2.  **API Keys**: Many sources require API keys. The script checks:
    -   `/root/Tools/apikeys.txt`
    -   `./apikeys.txt`
    -   Environment variables
    Supported keys include: `shodan`, `virustotal`, `otx`, `riskiq_user`, `riskiq_key`, `urlscan`, `securitytrails`, `censys`, `netlas`, `fofa_key`, `criminalip`, `whoisjson`, `ipinfo`, and `ipapisis`.

    *Note: If no API keys are provided, it will still use local resolution, Google DoH, crt.sh, and HackerTarget.*

### Usage

**Single IP (Full Analysis):**
```bash
python3 iptohost.py -ip 1.2.3.4
```

**Batch (File or CIDR Range):**
```bash
python3 iptohost.py -f ips.txt
python3 iptohost.py -r 1.2.3.0/24
```

**JSON Output:**
```bash
python3 iptohost.py -ip 1.2.3.4 --json
```

### Features

-   **Active Resolutions**: Hostnames that currently resolve to the target IP.
-   **Historical Findings**: Passive DNS, certificate transparency records, and historical OSINT database entries.
-   **VT Score**: Displays VirusTotal malicious detection ratio for the IP.