"""
CHAT MODE - FUNCTIONALITY 2 ONLY
Exact replica of client.py behavior with authentication
"""
import requests
import time
import json
import sys
import getpass
from prompt_toolkit import prompt

def get_args():
    session_id = None
    base_url = "http://localhost:8000"
    username = None
    password = None

    args = sys.argv[1:]

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
            print("Usage: python chat.py SESSION_ID [--session SESSION_ID] [--url BASE_URL] [--username USERNAME] [--password PASSWORD]")
            print("\nExamples:")
            print("  python chat.py session_123 --username admin --password admin123")
            print("  python chat.py session_123 (will prompt for credentials)")
            sys.exit(1)

    return session_id, base_url, username, password


def exact_client_replica():
    """Exact replica of client.py behavior with authentication"""
    session_id, base_url, username, password = get_args()

    # Authentication
    print("🔐 AUTHENTICATION REQUIRED")
    print("="*40)
    
    if not username:
        username = input("👤 Username: ")
    if not password:
        password = getpass.getpass("🔐 Password: ")
    
    # Login
    access_token = None
    user_info = None
    
    try:
        login_url = f"{base_url}/api/auth/login"
        login_payload = {
            "username": username,
            "password": password
        }
        response = requests.post(login_url, json=login_payload, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            access_token = data['access_token']
            user_info = {
                'id': data['user_id'],
                'username': data['username']
            }
            print(f"✅ Successfully logged in as {data['username']}")
        else:
            error_msg = response.json().get('detail', 'Login failed')
            print(f"❌ Login failed: {error_msg}")
            
            # Try default admin credentials
            if username != "admin":
                print("⚠️  Trying default admin credentials...")
                login_payload = {
                    "username": "admin",
                    "password": "admin123"
                }
                response = requests.post(login_url, json=login_payload, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    access_token = data['access_token']
                    user_info = {
                        'id': data['user_id'],
                        'username': data['username']
                    }
                    print(f"✅ Logged in as admin")
                else:
                    print("❌ Could not login with any credentials")
                    return
    except Exception as e:
        print(f"❌ Login error: {e}")
        return
    
    # Authentication headers
    def get_auth_headers():
        if not access_token:
            return {}
        return {"Authorization": f"Bearer {access_token}"}
    
    print(f"\n🤖 EXACT CLIENT.PY REPLICA - AUTHENTICATED")
    print(f"📝 Session: {session_id}")
    print(f"👤 User: {user_info['username']}")
    print("="*60)

    # FIRST: Fetch history like --history
    try:
        url = f"{base_url}/api/sessions/{session_id}/chat"
        params = {"limit": 50}
        headers = get_auth_headers()
        response = requests.get(url, params=params, headers=headers, timeout=None)

        if response.status_code == 200:
            messages = response.json()
            print(f"✅ {len(messages)} messages found")

            print("\n" + "="*60)
            print(f"CHAT HISTORY - Session: {session_id}")
            print("="*60)

            for msg in messages[-10:]:
                role_icon = "👤" if msg.get("role") == "user" else "🤖"
                timestamp = msg.get("created_at", "")
                if "T" in timestamp:
                    timestamp = timestamp.split("T")[1][:8]
                content = msg.get("content", "")
                username = msg.get('username', 'Unknown')
                if len(content) > 100:
                    content = content[:100] + "..."
                print(f"{role_icon} {username} [{timestamp}] {msg.get('role', '').upper()}:")
                print(f"   {content}")
                print("-"*40)

            # Last assistant message ID
            last_assistant_id = None
            for msg in reversed(messages):
                if msg.get('role') == 'assistant':
                    last_assistant_id = msg.get('id')
                    break

        else:
            print(f"❌ HTTP error: {response.status_code}")
            if response.status_code == 401:
                print("❌ Authentication expired")
            elif response.status_code == 403:
                print("❌ Access denied - you don't have permission to view this session")
            elif response.status_code == 404:
                print("❌ Session not found")
            else:
                print(f"Response: {response.text}")
            return

    except Exception as e:
        print(f"❌ Exception: {e}")
        return

    print("\n" + "="*60)
    print("Now, interactive chat (automatic assistant response)")
    print("Type 'exit' or 'quit' to end")
    print("="*60)

    while True:
        try:
            user_input = prompt("\nYou: ", multiline=True).strip()
            if not user_input:
                continue
            if user_input.lower() in ['exit', 'quit', 'sair']:
                print("👋 Goodbye!")
                break

            # Send user message
            print(f"🔁 Sending message '{user_input}'")
            try:
                url_post = f"{base_url}/api/chat/messages"
                payload = {
                    "session_id": session_id,
                    "content": user_input
                }
                headers = get_auth_headers()

                response = requests.post(url_post, json=payload, headers=headers, timeout=None)

                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ Message sent: {user_input}")
                    print(f"📝 From: {data.get('username', 'Unknown')}")
                    print(f"⏰ Sent at: {data.get('created_at', 'N/A')}")
                elif response.status_code == 401:
                    print("❌ Authentication expired - please restart and login again")
                    return
                elif response.status_code == 403:
                    print("❌ Access denied - you don't have permission to send messages in this session")
                    continue
                else:
                    print(f"❌ HTTP Error: {response.status_code}")
                    print(f"Response: {response.text}")
                    continue

            except Exception as e:
                print(f"❌ Error sending message: {e}")
                continue

            # Automatically wait for assistant response
            print("⏳ Waiting for assistant response automatically...")

            while True:
                try:
                    headers = get_auth_headers()
                    response = requests.get(url, params={"limit": 50}, headers=headers, timeout=None)
                    
                    if response.status_code == 200:
                        current_messages = response.json()

                        # Collect messages AFTER last assistant
                        new_messages = []
                        found_last = last_assistant_id is None

                        for msg in current_messages:
                            if not found_last:
                                if msg.get("id") == last_assistant_id:
                                    found_last = True
                                continue
                            new_messages.append(msg)

                        if new_messages:
                            print("\n" + "="*60)
                            print("📜 NEW CHAT MESSAGES")
                            print("="*60)

                            for msg in new_messages:
                                if msg.get("role") == "user":
                                    icon = "👤"
                                elif msg.get("role") == "assistant":
                                    icon = "🤖"
                                else:
                                    icon = "📢"
                                
                                timestamp = msg.get("created_at", "")
                                if "T" in timestamp:
                                    timestamp = timestamp.split("T")[1][:8]
                                
                                username = msg.get('username', 'Unknown')

                                print(f"{icon} {username} [{timestamp}]:")
                                print(msg.get("content", ""))
                                print("-"*40)

                            # Update last assistant ID
                            for msg in reversed(new_messages):
                                if msg.get("role") == "assistant":
                                    last_assistant_id = msg.get("id")
                                    break

                            break
                        else:
                            print("⏳ Waiting for assistant response...", end="\r")
                            time.sleep(3)
                    elif response.status_code == 401:
                        print("❌ Authentication expired - please restart and login again")
                        return
                    else:
                        print(f"❌ Error checking messages: {response.status_code}")
                        time.sleep(3)

                except Exception as e:
                    print(f"❌ Exception while waiting: {e}")
                    time.sleep(3)

        except KeyboardInterrupt:
            print("\n\n👋 Chat ended by user")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    exact_client_replica()
