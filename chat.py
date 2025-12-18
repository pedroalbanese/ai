"""
CHAT MODE - FUNCTIONALITY 2 ONLY
Exact replica of client.py behavior with authentication
Includes WATCH MODE (read-only)
"""

import requests
import time
import sys
import getpass
from prompt_toolkit import prompt

# --------------------------------------------------
# ARGUMENTS
# --------------------------------------------------

def get_args():
    session_id = None
    base_url = "http://localhost:8000"
    username = None
    password = None
    watch_mode = False

    args = sys.argv[1:]

    if "--watch" in args:
        watch_mode = True

    if "--session" in args:
        i = args.index("--session")
        if i + 1 < len(args):
            session_id = args[i + 1]

    if "--url" in args:
        i = args.index("--url")
        if i + 1 < len(args):
            base_url = args[i + 1]

    if "--username" in args:
        i = args.index("--username")
        if i + 1 < len(args):
            username = args[i + 1]

    if "--password" in args:
        i = args.index("--password")
        if i + 1 < len(args):
            password = args[i + 1]

    if session_id is None:
        if len(args) >= 1:
            session_id = args[0]
        else:
            print("Usage: python chat.py SESSION_ID [--session SESSION_ID] [--url BASE_URL] [--username USERNAME] [--password PASSWORD] [--watch]")
            print("\nExamples:")
            print("  python chat.py SESSION_ID [--watch]")
            print("  python chat.py SESSION_ID --username USER --password PASS")
            sys.exit(1)

    return session_id, base_url, username, password, watch_mode


# --------------------------------------------------
# MESSAGE PRINTING
# --------------------------------------------------

def print_new_messages(messages, last_msg_id):
    new_messages = []
    found_last = last_msg_id is None

    for msg in messages:
        if not found_last:
            if msg.get("id") == last_msg_id:
                found_last = True
            continue
        new_messages.append(msg)

    for msg in new_messages:
        role = msg.get("role")
        icon = "👤" if role == "user" else "🤖"
        timestamp = msg.get("created_at", "")
        if "T" in timestamp:
            timestamp = timestamp.split("T")[1][:8]

        username = msg.get("username", "Unknown")

        print(f"{icon} {username} [{timestamp}]:")
        print(msg.get("content", ""))
        print("-" * 40)

    if new_messages:
        return new_messages[-1]["id"]

    return last_msg_id


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def exact_client_replica():
    session_id, base_url, username, password, watch_mode = get_args()

    print("🔐 AUTHENTICATION REQUIRED")
    print("=" * 40)

    if not username:
        username = input("👤 Username: ")
    if not password:
        password = getpass.getpass("🔐 Password: ")

    # LOGIN
    try:
        response = requests.post(
            f"{base_url}/api/auth/login",
            json={"username": username, "password": password},
            timeout=10
        )

        if response.status_code != 200:
            print("❌ Login failed")
            return

        data = response.json()
        access_token = data["access_token"]
        user_info = data["username"]

        print(f"✅ Logged in as {user_info}")

    except Exception as e:
        print(f"❌ Login error: {e}")
        return

    def auth_headers():
        return {"Authorization": f"Bearer {access_token}"}

    print("\n" + "=" * 60)
    print(f"📝 Session: {session_id}")
    print(f"👤 User: {user_info}")

    if watch_mode:
        print("👀 MODE: WATCH (READ-ONLY)")
    else:
        print("💬 MODE: INTERACTIVE CHAT")

    print("=" * 60)

    # INITIAL HISTORY
    try:
        response = requests.get(
            f"{base_url}/api/sessions/{session_id}/chat",
            params={"limit": 50},
            headers=auth_headers(),
            timeout=None
        )

        if response.status_code != 200:
            print("❌ Cannot access session")
            return

        messages = response.json()
        last_msg_id = None

        print("\n📜 CHAT HISTORY")
        print("=" * 60)
        for msg in messages[-10:]:
            icon = "👤" if msg["role"] == "user" else "🤖"
            print(f"{icon} {msg.get('username','Unknown')}:")
            print(msg.get("content", ""))
            print("-" * 40)

        if messages:
            last_msg_id = messages[-1]["id"]

    except Exception as e:
        print(f"❌ Error loading history: {e}")
        return

    # --------------------------------------------------
    # WATCH MODE
    # --------------------------------------------------
    if watch_mode:
        print("\n📡 Watching chat in real-time (Ctrl+C to exit)")
        print("=" * 60)

        while True:
            try:
                response = requests.get(
                    f"{base_url}/api/sessions/{session_id}/chat",
                    params={"limit": 50},
                    headers=auth_headers(),
                    timeout=None
                )

                if response.status_code == 200:
                    messages = response.json()
                    last_msg_id = print_new_messages(messages, last_msg_id)
                    time.sleep(3)

                elif response.status_code in (401, 403):
                    print("❌ Access lost")
                    break
                else:
                    time.sleep(3)

            except KeyboardInterrupt:
                print("\n👋 Watch mode ended")
                break

        return

    # --------------------------------------------------
    # INTERACTIVE CHAT MODE
    # --------------------------------------------------
    print("\n💬 Interactive chat started (type 'exit' to quit)")
    print("=" * 60)

    while True:
        try:
            user_input = prompt("\nYou: ", multiline=True).strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "sair"):
                print("👋 Goodbye!")
                break

            # SEND MESSAGE
            response = requests.post(
                f"{base_url}/api/chat/messages",
                json={"session_id": session_id, "content": user_input},
                headers=auth_headers(),
                timeout=None
            )

            if response.status_code != 200:
                print("❌ Failed to send message")
                continue

            # WAIT FOR RESPONSE
            print("⏳ Waiting for assistant...")
            while True:
                response = requests.get(
                    f"{base_url}/api/sessions/{session_id}/chat",
                    params={"limit": 50},
                    headers=auth_headers(),
                    timeout=None
                )

                if response.status_code == 200:
                    messages = response.json()
                    new_last = print_new_messages(messages, last_msg_id)
                    if new_last != last_msg_id:
                        last_msg_id = new_last
                        break

                time.sleep(3)

        except KeyboardInterrupt:
            print("\n👋 Chat ended")
            break


# --------------------------------------------------
# ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    exact_client_replica()
