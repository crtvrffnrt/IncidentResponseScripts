#!/usr/bin/env python3

import argparse
import csv
import os
import sys
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Optional, Dict, Any, List

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
DEFAULT_WORKERS = 8


def status(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def get_token(tenant_id, client_id, client_secret, session: requests.Session):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": GRAPH_SCOPE,
        "grant_type": "client_credentials"
    }
    r = session.post(url, data=data, timeout=60)
    r.raise_for_status()
    return r.json()["access_token"]


def read_unique_message_ids(path) -> List[str]:
    with open(path, encoding="utf-8") as f:
        return list(dict.fromkeys(line.strip() for line in f if line.strip()))


def graph_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


def escape_filter_value(value: str) -> str:
    return value.replace("'", "''")


def format_recipients(recipients: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    if not recipients:
        return None
    addresses = []
    for recipient in recipients:
        address = recipient.get("emailAddress", {}).get("address")
        if address:
            addresses.append(address)
    return "; ".join(addresses) if addresses else None


def load_user_values(value: str) -> List[str]:
    if os.path.isfile(value):
        with open(value, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.lstrip().startswith("#")]
    return [part.strip() for part in value.split(",") if part.strip()]


def graph_get(token: str, url: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
    return requests.get(url, headers=graph_headers(token), params=params, timeout=60)


def list_users(token: str) -> Iterable[Dict[str, Any]]:
    url = f"{GRAPH_BASE}/users"
    params = {"$select": "id,userPrincipalName", "$top": "999"}

    while url:
        r = graph_get(token, url, params=params)
        if r.status_code != 200:
            return
        data = r.json()
        for user in data.get("value", []):
            yield user
        url = data.get("@odata.nextLink")
        params = None


def search_user_message(
    token: str,
    user_id: str,
    mailbox: str,
    message_id: str,
    folder_cache: Dict[str, Optional[str]],
    folder_lock: threading.Lock,
) -> Optional[Dict[str, Any]]:
    search_url = f"{GRAPH_BASE}/users/{user_id}/messages"
    params = {
        "$filter": f"internetMessageId eq '{escape_filter_value(message_id)}'",
        "$select": "id,subject,from,toRecipients,receivedDateTime,sentDateTime,parentFolderId"
    }
    r = graph_get(token, search_url, params=params)
    if r.status_code != 200:
        return None

    msgs = r.json().get("value", [])
    if not msgs:
        return None

    msg = msgs[0]
    folder_id = msg.get("parentFolderId")
    folder_name = None
    if folder_id:
        cache_key = f"{user_id}:{folder_id}"
        with folder_lock:
            folder_name = folder_cache.get(cache_key)
        if folder_name is None and cache_key not in folder_cache:
            folder_name = resolve_folder(token, user_id, folder_id)
            with folder_lock:
                folder_cache[cache_key] = folder_name
    return {
        "Mailbox": mailbox,
        "MessageId": message_id,
        "Subject": msg.get("subject"),
        "From": msg.get("from", {}).get("emailAddress", {}).get("address"),
        "To": format_recipients(msg.get("toRecipients")),
        "SentTime": msg.get("sentDateTime"),
        "ReceivedTime": msg.get("receivedDateTime"),
        "Folder": folder_name,
        "ExistsInMailbox": True
    }


def find_message(
    token: str,
    message_id: str,
    selected_users: Optional[List[str]],
    users: Optional[List[Dict[str, Any]]],
    folder_cache: Dict[str, Optional[str]],
    folder_lock: threading.Lock,
) -> Dict[str, Any]:
    if selected_users:
        for upn in selected_users:
            result = search_user_message(token, upn, upn, message_id, folder_cache, folder_lock)
            if result:
                return result
        return empty_result(message_id, selected_users[0])

    for user in users or []:
        result = search_user_message(
            token,
            user["id"],
            user["userPrincipalName"],
            message_id,
            folder_cache,
            folder_lock,
        )
        if result:
            return result

    return empty_result(message_id, None)


def empty_result(message_id: str, mailbox: Optional[str]) -> Dict[str, Any]:
    return {
        "Mailbox": mailbox,
        "MessageId": message_id,
        "Subject": None,
        "From": None,
        "To": None,
        "SentTime": None,
        "ReceivedTime": None,
        "Folder": None,
        "ExistsInMailbox": False
    }


def resolve_folder(token: str, user_id: str, folder_id: str):
    url = f"{GRAPH_BASE}/users/{user_id}/mailFolders/{folder_id}"
    r = graph_get(token, url)
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
    parser.add_argument(
        "--user",
        action="append",
        default=[],
        metavar="UPN",
        help="Scope searches to one or more mailbox UPNs. Repeat the flag or pass comma-separated values.",
    )
    parser.add_argument(
        "--upn",
        action="append",
        default=[],
        metavar="UPN",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Concurrent Graph lookups to run while searching message IDs.",
    )
    args = parser.parse_args()

    session = requests.Session()

    status("Acquiring Microsoft Graph token...")
    token = get_token(args.tenant_id, args.client_id, args.client_secret, session)

    status(f"Reading message IDs from {args.input}...")
    message_ids = read_unique_message_ids(args.input)
    status(f"Loaded {len(message_ids)} unique message IDs.")

    if not message_ids:
        print("No message IDs found in input.")
        return

    selected_users: List[str] = []
    for value in args.user + args.upn:
        selected_users.extend(load_user_values(value))
    selected_users = list(dict.fromkeys(selected_users))

    users = None
    if selected_users:
        status(f"Mailbox scope: {', '.join(selected_users)}")
    else:
        status("Mailbox scope: all users")
        status("Loading user list once from Microsoft Graph...")
        users = list(list_users(token))
        status(f"Loaded {len(users)} users.")

    workers = max(1, args.workers)
    status(f"Searching {len(message_ids)} message IDs with {workers} workers...")

    folder_cache: Dict[str, Optional[str]] = {}
    folder_lock = threading.Lock()
    rows_by_message_id: Dict[str, Dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(
                find_message,
                token,
                mid,
                selected_users,
                users,
                folder_cache,
                folder_lock,
            ): mid
            for mid in message_ids
        }

        completed = 0
        for future in as_completed(future_map):
            mid = future_map[future]
            completed += 1
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover - defensive runtime reporting
                status(f"[{completed}/{len(message_ids)}] {mid}: error - {exc}")
                result = empty_result(mid, selected_users[0] if selected_users else None)
            else:
                state = "found" if result.get("ExistsInMailbox") else "not found"
                mailbox = result.get("Mailbox") or (", ".join(selected_users) if selected_users else "all users")
                status(f"[{completed}/{len(message_ids)}] {mid}: {state} ({mailbox})")
            rows_by_message_id[mid] = result

    rows = [rows_by_message_id[mid] for mid in message_ids if mid in rows_by_message_id]
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    status(f"Wrote {len(rows)} records to {args.output}")


if __name__ == "__main__":
    main()
