# VPN Checker (Incident Response)

A small incident-response helper that checks a list of IPs for VPN indicators using **ipapi.is** and prints a colorized, IR‑oriented overview. VPN hits are flagged as **MALICIOUS** by design to help quickly triage suspicious logins or network activity.

## Features

- Accepts an input list of IPs via `-i` (defaults to `ips.txt`)
- Colorized output for fast triage
- Summary totals (VPN / non‑VPN / unknown)
- Defensive checks for missing dependencies and API key

## Requirements

- `bash`
- `curl`
- `jq`
- An API key from **ipapi.is**

## Setup

1) **Install dependencies**

- Ubuntu/Debian:
  ```bash
  sudo apt-get update && sudo apt-get install -y jq curl
  ```

- macOS (Homebrew):
  ```bash
  brew install jq curl
  ```

2) **Create API key file**

The script expects the file `/Tools/apikeys.txt` with an exported variable:

```bash
# /Tools/apikeys.txt
export ipapisisapi="YOUR_API_KEY"
```

3) **Prepare input file**

Create `ips.txt` (or another file and pass it with `-i`).

```text
# Example IP list
8.8.8.8
1.1.1.1
203.0.113.10
```

## Usage

```bash
./vpnchecker.sh -i ips.txt
```

If `-i` is omitted, it defaults to `ips.txt`.

## Output

The script prints a table and a short summary:

- **MALICIOUS** — VPN detected (`is_vpn=true`)
- **OK** — not a VPN (`is_vpn=false`)
- **UNKNOWN** — no clear determination

Example:

```
Incident Response: VPN Signal Check
IP                 IsVPN    VPNProvider          Flag
--                 -----    -----------          ----
203.0.113.10        true     ExampleVPN           MALICIOUS
1.1.1.1             false    N/A                  OK

Overview
Total IPs: 2
VPN (malicious): 1
Not VPN: 1
Unknown: 0
```

## Notes for Incident Response

- This script **only flags VPN signals**. Treat results as one signal among many.
- A VPN match is marked **MALICIOUS** to emphasize potential risk in IR workflows.
- Combine with other telemetry (geo, ASN, device, MFA, user behavior) before acting.

## Troubleshooting

- **`jq` not found**: install `jq` and retry.
- **API key error**: ensure `/Tools/apikeys.txt` exists and `ipapisisapi` is exported.
- **No results / unknown**: the upstream API may not return VPN details for all IPs.

## License

MIT (or your preferred license)
