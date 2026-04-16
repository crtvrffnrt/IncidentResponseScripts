Incident Response Purpose
  Use this script after an analyst has already identified suspicious or affected
  Internet Message IDs and now needs mailbox context for those messages.

  Typical use case:
    - A Microsoft 365 account is suspected or confirmed compromised
    - MailItemsAccessed, audit logs, or another source provides Internet Message IDs
    - This script enriches those IDs with message metadata from Microsoft Graph
    - The resulting CSV supports scoping, timeline building, and reporting

What the script returns
  - Mailbox where the message was found
  - Internet Message ID
  - Subject
  - From
  - To
  - SentTime
  - ReceivedTime
  - Folder
  - ExistsInMailbox

Required inputs
  --tenant-id       Microsoft Entra tenant ID
  --client-id       App registration client ID with Graph application permissions
  --client-secret   Client secret for the app registration
  --input           File containing Internet Message IDs, one per line
  --output          Output CSV path

Optional inputs
  --user            Scope the search to one or more mailbox UPNs. Recommended for IR.
                    Repeat the flag, pass comma-separated UPNs, or provide a file path.
  --workers         Number of concurrent Graph lookups. Default: 8
  --upn             Legacy alias for --user

Requirements
  - Python 3
  - requests Python package
  - Microsoft Graph app registration with:
      Mail.Read
      User.Read.All
      Directory.Read.All
    and tenant-wide admin consent
  - Authorization to investigate the target tenant and mailbox scope

Recommended workflow
  1. Create the Graph app registration:
       ./mailreadappcreate.sh
  2. Prepare a text file of Internet Message IDs
  3. Run this script against the affected mailbox or mailboxes
  4. Use the CSV output to enrich the initial evidence set

Examples
  Search one known compromised mailbox:
    python3 graph_mail_ir.py \
      --tenant-id <tenant-id> \
      --client-id <client-id> \
      --client-secret "<client-secret>" \
      --input message_ids.txt \
      --output mail_enrichment.csv \
      --user alice@contoso.com

  Search several affected mailboxes:
    python3 graph_mail_ir.py \
      --tenant-id <tenant-id> \
      --client-id <client-id> \
      --client-secret "<client-secret>" \
      --input message_ids.txt \
      --output mail_enrichment.csv \
      --user alice@contoso.com \
      --user bob@contoso.com

  Search mailboxes from a file:
    python3 graph_mail_ir.py \
      --tenant-id <tenant-id> \
      --client-id <client-id> \
      --client-secret "<client-secret>" \
      --input message_ids.txt \
      --output mail_enrichment.csv \
      --user affected_users.txt

  Search the full accessible tenant scope:
    python3 graph_mail_ir.py \
      --tenant-id <tenant-id> \
      --client-id <client-id> \
      --client-secret "<client-secret>" \
      --input message_ids.txt \
      --output mail_enrichment.csv

Operational notes
  - Without --user, the script loads all accessible users and may be slow in large tenants.
  - Input message IDs are deduplicated.
  - Output rows preserve the input order.
  - For each message ID, the script returns the first mailbox match found in the selected scope.
  - The output CSV uses semicolon delimiters.
