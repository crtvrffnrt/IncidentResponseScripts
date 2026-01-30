#!/usr/bin/env python3

import argparse
import csv
import os
import requests
from typing import Iterable, Optional, Set, Dict, Any

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def get_token(tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": GRAPH_SCOPE,
        "grant_type": "client_credentials"
    }
    r = requests.post(url, data=data)
    r.raise_for_status()
    return r.json()["access_token"]


def read_unique_message_ids(path) -> Set[str]:
    with open(path) as f:
        return {line.strip() for line in f if line.strip()}


def graph_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


def escape_filter_value(value: str) -> str:
    return value.replace("'", "''")


def list_users(token: str) -> Iterable[Dict[str, Any]]:
    headers = graph_headers(token)
    url = f"{GRAPH_BASE}/users"
    params = {"$select": "id,userPrincipalName"}

    while url:
        r = requests.get(url, headers=headers, params=params)
        if r.status_code != 200:
            return
        data = r.json()
        for user in data.get("value", []):
            yield user
        url = data.get("@odata.nextLink")
        params = None


def search_user_message(token: str, user_id: str, mailbox: str, message_id: str) -> Optional[Dict[str, Any]]:
    headers = graph_headers(token)
    search_url = f"{GRAPH_BASE}/users/{user_id}/messages"
    params = {
        "$filter": f"internetMessageId eq '{escape_filter_value(message_id)}'",
        "$select": "id,subject,from,receivedDateTime,sentDateTime,parentFolderId"
    }
    r = requests.get(search_url, headers=headers, params=params)
    if r.status_code != 200:
        return None

    msgs = r.json().get("value", [])
    if not msgs:
        return None

    msg = msgs[0]
    folder_name = resolve_folder(token, user_id, msg["parentFolderId"])
    return {
        "Mailbox": mailbox,
        "MessageId": message_id,
        "Subject": msg.get("subject"),
        "From": msg.get("from", {}).get("emailAddress", {}).get("address"),
        "SentTime": msg.get("sentDateTime"),
        "ReceivedTime": msg.get("receivedDateTime"),
        "Folder": folder_name,
        "ExistsInMailbox": True
    }


def find_message(token: str, message_id: str, upn: Optional[str]) -> Dict[str, Any]:
    if upn:
        result = search_user_message(token, upn, upn, message_id)
        if result:
            return result
        return empty_result(message_id, upn)

    for user in list_users(token):
        result = search_user_message(token, user["id"], user["userPrincipalName"], message_id)
        if result:
            return result

    return empty_result(message_id, None)


def empty_result(message_id: str, mailbox: Optional[str]) -> Dict[str, Any]:
    return {
        "Mailbox": mailbox,
        "MessageId": message_id,
        "Subject": None,
        "From": None,
        "SentTime": None,
        "ReceivedTime": None,
        "Folder": None,
        "ExistsInMailbox": False
    }


def resolve_folder(token, user_id, folder_id):
    url = f"{GRAPH_BASE}/users/{user_id}/mailFolders/{folder_id}"
    r = requests.get(url, headers=graph_headers(token))
    if r.status_code == 200:
        return r.json().get("displayName")
    return None


def load_help_text() -> str:
    help_path = os.path.join(os.path.dirname(__file__), "HELP.md")
    if not os.path.exists(help_path):
        return ""
    with open(help_path, "r", encoding="utf-8") as f:
        return f.read()


def main():
    help_text = load_help_text()
    parser = argparse.ArgumentParser(
        description="Search mailboxes for Internet Message IDs using Microsoft Graph.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=help_text
    )
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--client-secret", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--upn", help="Scope searches to a single mailbox UPN.")
    args = parser.parse_args()

    token = get_token(args.tenant_id, args.client_id, args.client_secret)
    message_ids = read_unique_message_ids(args.input)

    rows = []
    for mid in message_ids:
        result = find_message(token, mid, args.upn)
        rows.append(result)

    if not rows:
        print("No message IDs found in input.")
        return

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} records to {args.output}")


if __name__ == "__main__":
    main()
