# Incident Response Scripts

A collection of small helpers for incident response workflows.

## 1. Graph Mail IR (`graph_mail_ir.py`)

Enrich a list of suspicious mails across Exchange Online mailboxes using Microsoft Graph.

This script is intended for incident response after a Microsoft 365 user has been suspected or confirmed as compromised and mailbox content needs to be scoped quickly. The usual first step is to identify which mails were accessed for a given user. This tool takes that initial list of InternetMessageId`s and enriches it with additional mailbox context, such as:

- Subject
- Sender
- Recipients
- Sent timestamp
- Received timestamp
- Folder location
- Whether the message exists in the targeted mailbox

That makes it easier to turn a raw "message was accessed" list into a timeline that an analyst can use for triage, scoping, and reporting.

### Setup

1.  **Prepare Message IDs**: Create a file (e.g., `message_ids.txt`) containing the Internet Message IDs you want to enrich, one per line.
    - The script deduplicates repeated values automatically.
    - Empty lines are ignored.
2.  **Register App**: Run the helper script to create an Azure AD app with the Microsoft Graph application permissions required for mailbox-wide lookup.
    ```bash
    ./mailreadappcreate.sh
    ```
    Use `./mailreadappcreate.sh --help` to see the full help page with requirements, flags, and examples.
    If an app named `Graph-Mail-IR-Exporter` already exists, the helper removes it first and creates a fresh registration.
    This helper creates:
    - An app registration named `Graph-Mail-IR-Exporter`
    - A service principal
    - Microsoft Graph application permissions for `Mail.Read`, `User.Read.All`, and `Directory.Read.All`
    - Tenant-wide admin consent
    - A client secret for the app
    - Client-credential access for Graph API lookups, so the Python script can run without interactive user sign-in

    Optional helper flags:
    - `--app-name`: Override the app registration display name
    - `--secret-name`: Override the client secret display name

    *Treat the output as sensitive. Note the Tenant ID, Client ID, and Client Secret from the output and store them securely.*

### Usage

Execute the Python script using the credentials from the setup step:

```bash
python3 graph_mail_ir.py \
  --tenant-id <tenant-id> \
  --client-id <client-id> \
  --client-secret "<client-secret>" \
  --input message_ids.txt \
  --output mail_timeline.csv
```

Use `python3 graph_mail_ir.py --help` to view all flags, required inputs, output details, and incident-response examples directly from the script.

### Mailbox Scope

By default the script searches all users returned by Microsoft Graph and tries to match each Internet Message ID against every mailbox it can access.

Use `--user` when you already know which mailbox or mailboxes should be searched. This is the recommended mode during incident response because it reduces lookup time and keeps the scope focused on the affected user or users.

Examples:

```bash
# Search one mailbox
python3 graph_mail_ir.py \
  --tenant-id <tenant-id> \
  --client-id <client-id> \
  --client-secret "<client-secret>" \
  --input message_ids.txt \
  --output mail_timeline.csv \
  --user alice@contoso.com

# Search multiple specific mailboxes
python3 graph_mail_ir.py \
  --tenant-id <tenant-id> \
  --client-id <client-id> \
  --client-secret "<client-secret>" \
  --input message_ids.txt \
  --output mail_timeline.csv \
  --user alice@contoso.com \
  --user bob@contoso.com

# Search a comma-separated list or a file of UPNs
python3 graph_mail_ir.py \
  --tenant-id <tenant-id> \
  --client-id <client-id> \
  --client-secret "<client-secret>" \
  --input message_ids.txt \
  --output mail_timeline.csv \
  --user users.txt
```

Notes:
- `--user` can be repeated.
- `--user` also accepts comma-separated values.
- If the value points to a file, each non-empty line is treated as a mailbox UPN.
- The legacy `--upn` flag is still accepted for compatibility, but `--user` is the documented interface and should be used for new workflows.

### Output

The script writes a semicolon-delimited CSV with one row per Internet Message ID.

Columns:

- `Mailbox`: The mailbox that contained the message, if found
- `MessageId`: The Internet Message ID from the input file
- `Subject`: Message subject
- `From`: Sender address
- `To`: Recipient addresses joined as a string
- `SentTime`: Message sent timestamp
- `ReceivedTime`: Message received timestamp
- `Folder`: Mail folder name, when it can be resolved
- `ExistsInMailbox`: `True` if the message was found in the targeted mailbox scope, otherwise `False`

### Intended Incident-Response Flow

1. A suspicious mailbox is identified during incident response.
2. The responder extracts the relevant Internet Message IDs from audit data, mailbox evidence, or another source of mailbox activity.
3. `graph_mail_ir.py` is run against those IDs.
4. The output CSV is used to enrich the initial evidence set with message metadata.
5. The resulting dataset can then be used to build a timeline, identify affected mail, and support scoping or reporting.

This script does not try to prove compromise by itself. Its purpose is to enrich evidence that already points to mailbox access or message interaction.

### Operational Notes

- If you omit `--user`, the script searches all accessible users and may take longer on large tenants.
- Results are returned in the same order as the input file.
- The script skips duplicate Internet Message IDs to avoid repeated lookups.
- For each Internet Message ID, the script reports the first mailbox match it finds in the selected scope.

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

## 3. URL IR (`urlir.sh`)

Checks a suspicious URL with a compact SOC-friendly verdict. The script first resolves the URL host and enriches the first resolved IP, then checks URL reputation, then checks the host and root domain.

### Setup & Requirements

Install `jq`, `dig`, `curl`, `base64`, and `python3`.

API keys are loaded from `/root/Tools/apikeys.txt`. The script verifies that the required key variables exist before starting. Cloudflare Radar is verified with `/user/tokens/verify`; if the token is invalid during runtime, that source is skipped and the other checks continue.

### Usage

```bash
./urlir.sh https://example.com/path
./urlir.sh -file URLs.txt
```

Cloudflare Radar is automatic: the script first searches for an existing URL Scanner result, uses it when available, and only creates a new scan when no usable result exists. File mode reads one URL per non-empty line and ignores lines starting with `#`.

### Output

The output is intentionally short:

- Resolved IP context
- URL reputation
- Host and root-domain reputation
- Traffic-light verdict: **CLEAN**, **SUSPICIOUS**, or **MALICIOUS**
- One-line source errors when an API is blocked, rate-limited, or unavailable

---

## 4. IP to Host (`iptohost.py`)

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
