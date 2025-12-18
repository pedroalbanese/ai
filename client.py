"""
COMPUTER USE AGENT CLIENT - UPDATED VERSION
Complete Python client for the Computer Use Agent backend WITH AUTHENTICATION
"""
import asyncio
import json
import requests
import websockets
from datetime import datetime
from typing import Dict, List, Optional, Any
import sys
import getpass
import os
import time

class ComputerUseAgentClient:
    """Client for the Computer Use Agent Backend with Authentication"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.ws_base_url = self.base_url.replace('http://', 'ws://').replace('https://', 'wss://')
        self.session_id = None
        self.access_token = None
        self.user_info = None
        self.websocket = None
        
    # ============== AUTHENTICATION METHODS ==============
    def register(self, username: str, password: str, email: Optional[str] = None) -> bool:
        """Register a new user
        
        Args:
            username: Username for registration
            password: Password for the account
            email: Optional email address
            
        Returns:
            True if successful, False otherwise
            
        Example:
            >>> client = ComputerUseAgentClient()
            >>> if client.register("john_doe", "secure123", "john@example.com"):
            ...     print("✅ Registration successful")
            ... else:
            ...     print("❌ Registration failed")
        """
        url = f"{self.base_url}/api/auth/register"
        payload = {
            "username": username,
            "password": password,
            "email": email
        }
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 201:
                print(f"✅ User '{username}' registered successfully!")
                print(f"💡 You can now login with: python client.py --login")
                return True
            else:
                error_msg = response.json().get('detail', 'Registration failed')
                print(f"❌ Registration failed: {error_msg}")
                return False
                
        except requests.exceptions.ConnectionError:
            print(f"❌ Cannot connect to server at {self.base_url}")
            print("   Make sure the server is running: python chall.py")
            return False
        except Exception as e:
            print(f"❌ Registration error: {e}")
            return False
    
    def login(self, username: str, password: str) -> bool:
        """Login user
        
        Args:
            username: Username
            password: Password
            
        Returns:
            True if login successful, False otherwise
            
        Example:
            >>> client = ComputerUseAgentClient()
            >>> if client.login("john_doe", "secure123"):
            ...     print(f"✅ Logged in as {client.user_info['username']}")
            ...     print(f"🔑 Token: {client.access_token[:20]}...")
            ... else:
            ...     print("❌ Login failed")
        """
        url = f"{self.base_url}/api/auth/login"
        payload = {
            "username": username,
            "password": password
        }
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.access_token = data['access_token']
                self.user_info = {
                    'id': data['user_id'],
                    'username': data['username']
                }
                print(f"✅ Successfully logged in as {data['username']}")
                print(f"🔑 Token stored for session")
                return True
            else:
                error_msg = response.json().get('detail', 'Login failed')
                print(f"❌ Login failed: {error_msg}")
                return False
                
        except requests.exceptions.ConnectionError:
            print(f"❌ Cannot connect to server at {self.base_url}")
            print("   Make sure the server is running: python chall.py")
            return False
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False
    
    def logout(self):
        """Logout current user"""
        self.access_token = None
        self.user_info = None
        self.session_id = None
        print("✅ Logged out")
    
    def get_current_user(self) -> Optional[Dict]:
        """Get current user info
        
        Returns:
            User info dictionary or None if not logged in
            
        Example:
            >>> user = client.get_current_user()
            >>> if user:
            ...     print(f"👤 Currently logged in as: {user['username']}")
        """
        if not self.access_token:
            print("⚠️  Not logged in")
            return None
        
        url = f"{self.base_url}/api/auth/me"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        
        try:
            response = requests.get(url, headers=headers, timeout=600)
            response.raise_for_status()
            return response.json()
        except:
            print("❌ Failed to get user info - token may be invalid")
            return None
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return self.access_token is not None and self.user_info is not None
    
    def get_auth_headers(self) -> Dict:
        """Get authentication headers for requests"""
        if not self.access_token:
            return {}
        return {"Authorization": f"Bearer {self.access_token}"}
    
    # ============== SESSION MANAGEMENT ==============
    def create_session(self, name: Optional[str] = None, 
                       vm_config: Optional[Dict] = None,
                       session_password: Optional[str] = None,
                       is_public: bool = False,
                       max_users: int = 1) -> Dict:
        """Create a new session (requires authentication)
        
        Args:
            name: Optional session name
            vm_config: Optional VM configuration dictionary
            session_password: Password to access the session (auto-generated if None)
            is_public: Whether session is publicly visible
            max_users: Maximum number of users allowed in session
            
        Returns:
            Dictionary containing session information
            
        Example:
            >>> client = ComputerUseAgentClient()
            >>> client.login("john_doe", "password")
            >>> session = client.create_session(
            ...     name="Development Session",
            ...     vm_config={"cpu": 4, "memory": 8192},
            ...     session_password="mysecret",
            ...     is_public=False,
            ...     max_users=3
            ... )
            ✅ Session created with ID: sess_abc123
            🔐 Session Password: mysecret
            📊 Status: pending
            👥 Max users: 3
            🔒 Private session
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to create a session")
            return {}
        
        url = f"{self.base_url}/api/sessions"
        payload = {
            "name": name,
            "vm_config": vm_config or {},
            "session_password": session_password,
            "is_public": is_public,
            "max_users": max_users
        }
        
        headers = self.get_auth_headers()
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            self.session_id = data["session"]["id"]
            session_password = data.get("session_password", "auto-generated")
            
            print(f"✅ Session created with ID: {self.session_id}")
            if session_password:
                print(f"🔐 Session Password: {session_password}")
                print("💡 Share this password with others to join the session")
            print(f"📊 Status: {data['session']['status']}")
            print(f"👥 Max users: {data['session']['max_users']}")
            print(f"🔒 {'Public' if data['session']['is_public'] else 'Private'} session")
            
            if data.get('vnc_url'):
                print(f"🖥️  VNC URL: {data['vnc_url']}")
            if data.get('websocket_url'):
                print(f"📡 WebSocket: {data['websocket_url']}")
            
            return data
            
        except requests.exceptions.ConnectionError:
            print(f"❌ Cannot connect to server at {self.base_url}")
            print("   Make sure the server is running: python chall.py")
            return {}
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            else:
                print(f"❌ HTTP Error: {e.response.status_code}")
                print(f"   {e.response.json().get('detail', 'Unknown error')}")
            return {}
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return {}
    
    def join_session(self, session_id: str, session_password: str) -> bool:
        """Join an existing session with password
        
        Args:
            session_id: Session identifier
            session_password: Password to join the session
            
        Returns:
            True if successful, False otherwise
            
        Example:
            >>> client = ComputerUseAgentClient()
            >>> client.login("john_doe", "password")
            >>> if client.join_session("sess_abc123", "mysecret"):
            ...     print("✅ Successfully joined session")
            ...     print(f"🔗 Session ID: {client.session_id}")
            ... else:
            ...     print("❌ Failed to join session")
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to join a session")
            return False
        
        url = f"{self.base_url}/api/sessions/join"
        payload = {
            "session_id": session_id,
            "session_password": session_password
        }
        
        headers = self.get_auth_headers()
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                self.session_id = session_id
                print(f"✅ Successfully joined session {session_id}")
                return True
            else:
                error_msg = response.json().get('detail', 'Join failed')
                print(f"❌ Failed to join session: {error_msg}")
                return False
                
        except requests.exceptions.ConnectionError:
            print(f"❌ Cannot connect to server at {self.base_url}")
            return False
        except Exception as e:
            print(f"❌ Join error: {e}")
            return False
    
    def list_sessions(self, public_only: bool = False) -> List[Dict]:
        """List all sessions accessible to current user
        
        Args:
            public_only: If True, only list public sessions
            
        Returns:
            List of session dictionaries
            
        Example:
            >>> sessions = client.list_sessions()
            >>> print(f"Found {len(sessions)} sessions you can access")
            >>> for session in sessions:
            ...     print(f"{session['id']}: {session['name']} ({session['status']})")
        """
        if not self.is_authenticated() and not public_only:
            print("⚠️  Not logged in - showing only public sessions")
            public_only = True
        
        if public_only:
            url = f"{self.base_url}/api/sessions/public"
            params = {}
        else:
            url = f"{self.base_url}/api/sessions"
            headers = self.get_auth_headers()
            params = {}
        
        try:
            if public_only:
                response = requests.get(url, params=params, timeout=5)
            else:
                response = requests.get(url, params=params, headers=headers, timeout=5)
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            else:
                print(f"❌ Error listing sessions: {e}")
            return []
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return []
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session details (requires access)
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session dictionary or None if not found/accessible
            
        Example:
            >>> session = client.get_session("sess_abc123")
            >>> if session:
            ...     print(f"Session {session['name']} is {session['status']}")
            ...     print(f"Owner: {session['username']}")
            ...     print(f"Users: {session['current_users']}/{session['max_users']}")
            ... else:
            ...     print("Session not found or no access")
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to view session details")
            return None
        
        url = f"{self.base_url}/api/sessions/{session_id}"
        headers = self.get_auth_headers()
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            elif e.response.status_code == 403:
                print("❌ Access denied - you don't have permission to view this session")
            elif e.response.status_code == 404:
                print(f"❌ Session {session_id} not found")
            else:
                print(f"❌ Error getting session: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return None
    
    def update_session(self, session_id: str, name: Optional[str] = None, 
                       status: Optional[str] = None, is_public: Optional[bool] = None,
                       max_users: Optional[int] = None) -> Dict:
        """Update a session (owner only)
        
        Args:
            session_id: Session identifier
            name: New session name
            status: New session status
            is_public: Whether session is public
            max_users: Maximum number of users
            
        Returns:
            Updated session dictionary
            
        Example:
            >>> client.update_session(
            ...     session_id="sess_abc123",
            ...     name="Updated Session Name",
            ...     is_public=True,
            ...     max_users=5
            ... )
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to update a session")
            return {}
        
        url = f"{self.base_url}/api/sessions/{session_id}"
        payload = {}
        if name is not None:
            payload["name"] = name
        if status is not None:
            payload["status"] = status
        if is_public is not None:
            payload["is_public"] = is_public
        if max_users is not None:
            payload["max_users"] = max_users
        
        headers = self.get_auth_headers()
        
        try:
            response = requests.put(url, json=payload, headers=headers, timeout=5)
            response.raise_for_status()
            print(f"✅ Session {session_id} updated successfully")
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            elif e.response.status_code == 403:
                print("❌ Access denied - only session owner can update")
            elif e.response.status_code == 404:
                print(f"❌ Session {session_id} not found")
            else:
                print(f"❌ Error updating session: {e}")
            return {}
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return {}
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session (owner only)
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if successful, False otherwise
            
        Example:
            >>> if client.delete_session("sess_abc123"):
            ...     print("Session deleted successfully")
            ... else:
            ...     print("Failed to delete session")
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to delete a session")
            return False
        
        url = f"{self.base_url}/api/sessions/{session_id}"
        headers = self.get_auth_headers()
        
        try:
            response = requests.delete(url, headers=headers, timeout=5)
            if response.status_code == 204:
                if self.session_id == session_id:
                    self.session_id = None
                print(f"✅ Session {session_id} deleted successfully")
                return True
            else:
                return False
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            elif e.response.status_code == 403:
                print("❌ Access denied - only session owner can delete")
            elif e.response.status_code == 404:
                print(f"❌ Session {session_id} not found")
            else:
                print(f"❌ Error deleting session: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return False
    
    def get_session_users(self, session_id: str) -> List[Dict]:
        """Get all users who have access to a session
        
        Args:
            session_id: Session identifier
            
        Returns:
            List of user dictionaries
            
        Example:
            >>> users = client.get_session_users("sess_abc123")
            >>> print(f"Session has {len(users)} users:")
            >>> for user in users:
            ...     print(f"  • {user['username']} ({user['access_level']})")
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to view session users")
            return []
        
        url = f"{self.base_url}/api/sessions/{session_id}/users"
        headers = self.get_auth_headers()
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            elif e.response.status_code == 403:
                print("❌ Access denied - you don't have permission to view this session")
            else:
                print(f"❌ Error getting session users: {e}")
            return []
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return []
    
    def get_connected_users(self, session_id: str) -> List[Dict]:
        """Get users currently connected via WebSocket
        
        Args:
            session_id: Session identifier
            
        Returns:
            List of connected user dictionaries
            
        Example:
            >>> connected = client.get_connected_users("sess_abc123")
            >>> print(f"{len(connected)} users currently connected:")
            >>> for user in connected:
            ...     print(f"  • {user['username']}")
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to view connected users")
            return []
        
        url = f"{self.base_url}/api/sessions/{session_id}/connected"
        headers = self.get_auth_headers()
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            elif e.response.status_code == 403:
                print("❌ Access denied - you don't have permission to view this session")
            else:
                print(f"❌ Error getting connected users: {e}")
            return []
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return []
    
    # ============== CHAT MANAGEMENT ==============
    def send_message(self, session_id: str, content: str) -> Optional[Dict]:
        """Send a chat message (requires session access)
        
        Args:
            session_id: Session identifier
            content: Message content
            
        Returns:
            Message dictionary or None if failed
            
        Example:
            >>> response = client.send_message(
            ...     session_id="sess_abc123",
            ...     content="Hello everyone, how are you?"
            ... )
            ✅ Message sent to session sess_abc123
            📝 From: john_doe
            📋 Content: Hello everyone, how are you?
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to send messages")
            return None
        
        url = f"{self.base_url}/api/chat/messages"
        payload = {
            "session_id": session_id,
            "content": content
        }
        
        headers = self.get_auth_headers()
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            print(f"✅ Message sent to session {session_id}")
            print(f"📝 From: {data.get('username', 'Unknown')}")
            print(f"📋 Content: {content[:50]}{'...' if len(content) > 50 else ''}")
            
            return data
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            elif e.response.status_code == 403:
                print("❌ Access denied - you don't have permission to send messages in this session")
            elif e.response.status_code == 404:
                print("   Endpoint /api/chat/messages not found")
                print("   Verify the server has this endpoint implemented")
            else:
                print(f"❌ Error sending message: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return None
    
    def get_chat_history(self, session_id: str, limit: int = 50) -> List[Dict]:
        """Get chat history (requires session access)
        
        Args:
            session_id: Session identifier
            limit: Maximum number of messages to retrieve
            
        Returns:
            List of message dictionaries
            
        Example:
            >>> history = client.get_chat_history("sess_abc123", limit=10)
            >>> for msg in history:
            ...     print(f"{msg['username']}: {msg['content'][:50]}...")
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to view chat history")
            return []
        
        url = f"{self.base_url}/api/sessions/{session_id}/chat"
        headers = self.get_auth_headers()
        params = {"limit": limit}
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            elif e.response.status_code == 403:
                print("❌ Access denied - you don't have permission to view chat history")
            else:
                print(f"❌ Error getting chat history: {e}")
            return []
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return []
    
    def print_chat_history(self, session_id: str, limit: int = 50):
        """Print formatted chat history
        
        Args:
            session_id: Session identifier
            limit: Maximum number of messages to display
            
        Example:
            >>> client.print_chat_history("sess_abc123")
            ============================================================
            CHAT HISTORY - Session: sess_abc123
            ============================================================
            👤 john_doe [10:30:00]:
               Hello everyone, how are you?
            ----------------------------------------
            🤖 AI Assistant [10:30:05]:
               I'm here to help! How can I assist you today?
            ----------------------------------------
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to view chat history")
            return
        
        messages = self.get_chat_history(session_id, limit)
        
        if not messages:
            print(f"📭 No messages found for session {session_id}")
            return
        
        print("\n" + "="*60)
        print(f"CHAT HISTORY - Session: {session_id}")
        print("="*60)
        
        for msg in messages:
            if msg["role"] == "user":
                role_icon = "👤"
            elif msg["role"] == "assistant":
                role_icon = "🤖"
            else:
                role_icon = "📢"
            
            timestamp = msg["created_at"].split("T")[1][:8] if "T" in msg["created_at"] else msg["created_at"]
            username = msg.get('username', 'Unknown')
            
            print(f"{role_icon} {username} [{timestamp}]:")
            print(f"   {msg['content']}")
            print("-"*40)
    
    # ============== STREAMING ==============
    def stream_session_updates(self, session_id: str):
        """Stream session updates via SSE (Server-Sent Events)
        
        Args:
            session_id: Session identifier
            
        Example:
            >>> client.stream_session_updates("sess_abc123")
            🔐 Authenticating for SSE stream...
            📡 Starting stream for session sess_abc123...
            Press Ctrl+C to stop
            
            ✅ Connected to session as john_doe
            👥 Users online: 3
            📊 [██████████░░░░░░░░░░] 50% - Starting virtual machine
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to stream updates")
            return
        
        url = f"{self.base_url}/api/sessions/{session_id}/stream"
        headers = self.get_auth_headers()
        
        print(f"🔐 Authenticating for SSE stream...")
        print(f"📡 Starting stream for session {session_id}...")
        print("Press Ctrl+C to stop\n")
        
        try:
            response = requests.get(url, headers=headers, stream=True, timeout=None)
            
            if response.status_code != 200:
                error_msg = response.json().get('detail', 'Stream failed')
                print(f"❌ Stream error: {error_msg}")
                return
            
            for line in response.iter_lines():
                if line:
                    line_str = line.decode('utf-8')
                    if line_str.startswith('data: '):
                        data = json.loads(line_str[6:])
                        self._handle_stream_event(data)
                        
        except KeyboardInterrupt:
            print("\n⏹️  Stream stopped by user")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            elif e.response.status_code == 403:
                print("❌ Access denied - you don't have permission to stream this session")
            else:
                print(f"❌ Stream error: {e}")
        except Exception as e:
            print(f"❌ Unexpected stream error: {e}")
    
    def _handle_stream_event(self, event: Dict):
        """Process stream events (internal method)"""
        event_type = event.get("type", "unknown")
        
        if event_type == "connected":
            session = event.get("session", {})
            user = event.get("user", {})
            print(f"✅ Connected to session '{session.get('name')}' as {user.get('username')}")
            
        elif event_type == "users_update":
            users = event.get("users", [])
            if users:
                print(f"👥 Users online ({len(users)}): {', '.join([u.get('username', 'Unknown') for u in users])}")
            
        elif event_type == "progress":
            step = event.get("step", 0)
            total = event.get("total", 1)
            message = event.get("message", "")
            percentage = event.get("percentage", 0)
            
            progress_bar = "█" * int(percentage / 5) + "░" * (20 - int(percentage / 5))
            print(f"📊 [{progress_bar}] {percentage:.0f}% - {message}")
            
        elif event_type == "activity":
            print(f"📝 {event.get('description', '')}")
            
        else:
            print(f"📨 {json.dumps(event, indent=2)}")
    
    # ============== WEBSOCKET WITH AUTH ==============
    async def connect_websocket(self, session_id: str):
        """Connect via WebSocket with authentication
        
        Args:
            session_id: Session identifier
            
        Example:
            >>> import asyncio
            >>> client = ComputerUseAgentClient()
            >>> client.login("john_doe", "password")
            >>> asyncio.run(client.connect_websocket("sess_abc123"))
            🔐 Authenticating WebSocket connection...
            🔗 Connecting WebSocket: ws://localhost:8000/api/sessions/sess_abc123/ws?token=...
            ✅ WebSocket connected successfully as john_doe!
            
            💬 Available commands:
              • chat <message>  - Send message
              • command <cmd>   - Execute command (editors+)
              • get_users       - List connected users
              • ping            - Test connection
              • quit            - Exit
            ========================================
            
            ⌨️  Type a command: chat Hello everyone
            📤 Sent: Hello everyone
            👤 john_doe: Hello everyone
            🤖 AI Assistant: Hello! How can I assist you today?
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to use WebSocket")
            return
        
        if not self.access_token:
            print("❌ No access token available")
            return
        
        ws_url = f"{self.ws_base_url}/api/sessions/{session_id}/ws?token={self.access_token}"
        
        print(f"🔐 Authenticating WebSocket connection...")
        print(f"🔗 Connecting WebSocket: {ws_url}")
        
        try:
            self.websocket = await websockets.connect(ws_url, timeout=10)
            print(f"✅ WebSocket connected successfully as {self.user_info['username']}!")
            
            # Start read and write tasks
            read_task = asyncio.create_task(self._read_websocket_messages())
            write_task = asyncio.create_task(self._handle_websocket_input(session_id))
            
            await asyncio.gather(read_task, write_task)
            
        except websockets.exceptions.ConnectionClosedError:
            print("❌ WebSocket connection closed by server")
        except asyncio.TimeoutError:
            print("❌ WebSocket connection timeout")
        except Exception as e:
            print(f"❌ WebSocket error: {e}")
        finally:
            if self.websocket:
                await self.websocket.close()
    
    async def _read_websocket_messages(self):
        """Read WebSocket messages (internal method)"""
        try:
            async for message in self.websocket:
                data = json.loads(message)
                self._handle_websocket_message(data)
        except websockets.exceptions.ConnectionClosed:
            print("📴 WebSocket connection closed")
        except Exception as e:
            print(f"❌ Error reading WebSocket message: {e}")
    
    async def _handle_websocket_input(self, session_id: str):
        """Handle user input for WebSocket (internal method)"""
        print("\n💬 Available commands:")
        print("  • chat <message>  - Send message")
        print("  • command <cmd>   - Execute command (editors+)")
        print("  • get_users       - List connected users")
        print("  • ping            - Test connection")
        print("  • quit            - Exit")
        print("="*40)
        
        while True:
            try:
                user_input = await asyncio.get_event_loop().run_in_executor(
                    None, input, "\n⌨️  Type a command: "
                )
                
                if user_input.lower() == 'quit':
                    print("👋 Exiting...")
                    break
                    
                elif user_input.lower() == 'ping':
                    await self.websocket.send(json.dumps({"type": "ping"}))
                    print("🏓 Ping sent")
                    
                elif user_input.lower() == 'get_users':
                    await self.websocket.send(json.dumps({"type": "get_users"}))
                    print("👥 Requested user list")
                    
                elif user_input.startswith('chat '):
                    message = user_input[5:]
                    await self.websocket.send(json.dumps({
                        "type": "chat",
                        "content": message
                    }))
                    print(f"📤 Sent: {message}")
                    
                elif user_input.startswith('command '):
                    command = user_input[8:]
                    await self.websocket.send(json.dumps({
                        "type": "command",
                        "command": command
                    }))
                    print(f"⚡ Command sent: {command}")
                    
                else:
                    print("❌ Unknown command. Use: chat, command, get_users, ping, quit")
                    
            except KeyboardInterrupt:
                print("\n👋 Interrupted by user")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def _handle_websocket_message(self, message: Dict):
        """Process WebSocket messages (internal method)"""
        msg_type = message.get("type", "unknown")
        
        if msg_type == "connected":
            print(f"✅ {message.get('message')}")
            
        elif msg_type == "disconnected":
            print(f"👋 {message.get('message')}")
            
        elif msg_type == "chat":
            username = message.get("username", "Unknown")
            role = message.get("role", "unknown")
            content = message.get("content", "")
            
            if role == "user":
                print(f"👤 {username}: {content}")
            elif role == "assistant":
                print(f"🤖 {username}: {content}")
            else:
                print(f"📢 {username}: {content}")
                
        elif msg_type == "agent_response":
            print(f"🤖 AI Assistant: {message.get('content', '')}")
            
        elif msg_type == "command_result":
            print(f"⚡ Result: {message.get('result', '')}")
            
        elif msg_type == "pong":
            print(f"🏓 Pong received at {message.get('timestamp', '')}")
            
        elif msg_type == "users_list":
            users = message.get("users", [])
            if users:
                print(f"👥 Connected users ({len(users)}):")
                for user in users:
                    print(f"  • {user.get('username', 'Unknown')}")
            else:
                print("👥 No other users connected")
            
        elif msg_type == "progress":
            print(f"📊 {message.get('data', {}).get('message', '')}")
            
        elif msg_type == "error":
            print(f"❌ Error: {message.get('message', 'Unknown error')}")
            
        else:
            print(f"📨 {json.dumps(message, indent=2)}")
    
    # ============== VNC ==============
    def get_vnc_info(self, session_id: str) -> Optional[Dict]:
        """Get VNC connection information (requires session access)
        
        Args:
            session_id: Session identifier
            
        Returns:
            VNC information dictionary or None if failed
            
        Example:
            >>> vnc_info = client.get_vnc_info("sess_abc123")
            >>> print(f"VNC Port: {vnc_info.get('vnc_port')}")
            >>> print(f"Password: {vnc_info.get('vnc_password')}")
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to view VNC info")
            return None
        
        url = f"{self.base_url}/api/sessions/{session_id}/vnc"
        headers = self.get_auth_headers()
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            elif e.response.status_code == 403:
                print("❌ Access denied - you don't have permission to view VNC info")
            elif e.response.status_code == 404:
                print(f"❌ Session {session_id} not found")
            else:
                print(f"❌ Error getting VNC info: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return None
    
    def print_vnc_info(self, session_id: str):
        """Print formatted VNC information
        
        Args:
            session_id: Session identifier
            
        Example:
            >>> client.print_vnc_info("sess_abc123")
            ============================================================
            VNC CONNECTION INFORMATION
            ============================================================
            🎮 Session: sess_abc123
            🔌 VNC Port: 5901
            🔑 VNC Password: abc123def
            📡 WebSocket VNC: ws://localhost:8000/api/sessions/sess_abc123/vnc/ws
            🌐 noVNC URL: http://localhost:6080/vnc.html?host=localhost&port=5901
            
            💡 To connect via VNC (requires token):
               1. Use WebSocket URL with token parameter
               2. Or use noVNC URL in browser
        """
        info = self.get_vnc_info(session_id)
        if not info:
            return
        
        print("\n" + "="*60)
        print("VNC CONNECTION INFORMATION")
        print("="*60)
        print(f"🎮 Session: {info.get('session_id', 'N/A')}")
        print(f"🔌 VNC Port: {info.get('vnc_port', 'N/A')}")
        print(f"🔑 VNC Password: {info.get('vnc_password', 'N/A')}")
        print(f"📡 WebSocket VNC: {info.get('websocket_url', 'N/A')}")
        print(f"🌐 noVNC URL: {info.get('novnc_url', 'N/A')}")
        
        if info.get('vnc_port'):
            print("\n💡 To connect via VNC (requires authentication):")
            print(f"   WebSocket URL with token: {info.get('websocket_url')}?token={self.access_token}")
            print(f"   Or use noVNC URL in browser (may require login)")
    
    # ============== ACTIVITIES ==============
    def get_session_activities(self, session_id: str, limit: int = 20) -> List[Dict]:
        """Get session activities (requires session access)
        
        Args:
            session_id: Session identifier
            limit: Maximum number of activities to retrieve
            
        Returns:
            List of activity dictionaries
            
        Example:
            >>> activities = client.get_session_activities("sess_abc123", limit=5)
            >>> for activity in activities:
            ...     print(f"{activity['created_at']}: {activity['description']}")
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to view activities")
            return []
        
        url = f"{self.base_url}/api/sessions/{session_id}/activities"
        headers = self.get_auth_headers()
        params = {"limit": limit}
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            elif e.response.status_code == 403:
                print("❌ Access denied - you don't have permission to view activities")
            else:
                print(f"❌ Error getting activities: {e}")
            return []
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return []
    
    def print_activities(self, session_id: str, limit: int = 20):
        """Print formatted session activities
        
        Args:
            session_id: Session identifier
            limit: Maximum number of activities to display
            
        Example:
            >>> client.print_activities("sess_abc123")
            ============================================================
            SESSION ACTIVITIES - Session: sess_abc123
            ============================================================
            📅 2024-01-15 10:30:00 - john_doe created session
            📅 2024-01-15 10:32:00 - jane_doe joined session
            📅 2024-01-15 10:35:00 - AI Assistant responded to message
        """
        activities = self.get_session_activities(session_id, limit)
        
        if not activities:
            print(f"📭 No activities found for session {session_id}")
            return
        
        print("\n" + "="*60)
        print(f"SESSION ACTIVITIES - Session: {session_id}")
        print("="*60)
        
        for activity in activities:
            timestamp = activity["created_at"].replace("T", " ")[:19]
            username = activity.get("username", "System")
            description = activity.get("description", "Unknown activity")
            
            print(f"📅 {timestamp} - {username} {description}")
    
    # ============== SYSTEM INFO ==============
    def health_check(self) -> Optional[Dict]:
        """Check system health (no authentication required)
        
        Returns:
            Health status dictionary or None if failed
            
        Example:
            >>> health = client.health_check()
            >>> print(f"System status: {health.get('status')}")
            >>> print(f"Total sessions: {health.get('total_sessions')}")
        """
        url = f"{self.base_url}/health"
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            print(f"❌ Health check error: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return None
    
    def get_stats(self) -> Optional[Dict]:
        """Get system statistics (requires authentication)
        
        Returns:
            Statistics dictionary or None if failed
            
        Example:
            >>> stats = client.get_stats()
            >>> print(f"Your sessions: {stats.get('user_sessions', 0)}")
            >>> print(f"Total sessions: {stats.get('total_sessions_all', 0)}")
        """
        if not self.is_authenticated():
            print("❌ You must be logged in to view statistics")
            return None
        
        url = f"{self.base_url}/stats"
        headers = self.get_auth_headers()
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("❌ Authentication failed - please login again")
                self.logout()
            else:
                print(f"❌ Error getting statistics: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return None
    
    def print_system_info(self):
        """Print system information
        
        Example:
            >>> client.print_system_info()
            ============================================================
            SYSTEM INFORMATION
            ============================================================
            🏥 Status: HEALTHY
            🕐 Last check: 2024-01-15T10:30:00Z
            🗄️  Total sessions: 15
            🔗 Active connections: 8
            
            👤 Your information:
               • User ID: user_abc123
               • Username: john_doe
               • Your sessions: 3
        """
        health = self.health_check()
        if not health:
            return
        
        stats = self.get_stats()
        
        print("\n" + "="*60)
        print("SYSTEM INFORMATION")
        print("="*60)
        print(f"🏥 Status: {health.get('status', 'unknown').upper()}")
        print(f"🕐 Last check: {health.get('timestamp', 'N/A')}")
        print(f"🗄️  Total sessions: {health.get('total_sessions', 0)}")
        print(f"🔗 Active connections: {health.get('active_connections', 0)}")
        
        if stats:
            print(f"\n👤 Your information:")
            print(f"   • User ID: {stats.get('user_info', {}).get('user_id', 'N/A')}")
            print(f"   • Username: {stats.get('user_info', {}).get('username', 'N/A')}")
            print(f"   • Your sessions: {stats.get('user_sessions', 0)}")
            
            if 'status_counts' in stats:
                print(f"\n📊 Your session statuses:")
                for status, count in stats['status_counts'].items():
                    print(f"   • {status}: {count}")
    
    # ============== DEMO FUNCTIONS ==============
    def run_auth_demo(self):
        """Run a complete authentication demonstration
        
        Example:
            >>> client.run_auth_demo()
            🚀 STARTING AUTHENTICATION DEMONSTRATION
            ============================================================
            
            1. Checking system health...
               ✅ System healthy
            
            2. Registering new user...
               ✅ User 'demo_user' registered successfully!
            
            3. Logging in...
               ✅ Successfully logged in as demo_user
            
            4. Creating new session...
               ✅ Session created with ID: sess_demo123
               🔐 Session Password: abc123def
            
            5. Joining session (simulating another user)...
               ⚠️  Would require another client instance
            
            6. Sending chat message...
               ✅ Message sent to session sess_demo123
            
            7. Getting session users...
               Session has 1 users:
                 • demo_user (admin)
            
            8. System statistics...
               👤 Your sessions: 1
            
            🎉 AUTHENTICATION DEMONSTRATION COMPLETED!
            📋 Created session ID: sess_demo123
            🔑 Token stored for future use
            ============================================================
        """
        print("🚀 STARTING AUTHENTICATION DEMONSTRATION")
        print("="*60)
        
        try:
            # 1. Check health
            print("\n1. Checking system health...")
            health = self.health_check()
            if not health:
                print("❌ System not responding")
                return
            
            print(f"   ✅ System {health.get('status', 'unknown')}")
            
            # 2. Register user
            print("\n2. Registering new user...")
            import random
            demo_username = f"demo_user_{random.randint(1000, 9999)}"
            demo_password = "demo123"
            
            if not self.register(demo_username, demo_password, "demo@example.com"):
                print("⚠️  Using existing credentials...")
                # Try to login with demo credentials
                if not self.login("admin", "admin123"):
                    print("❌ Could not login with default credentials")
                    return
            
            # 3. Login
            print("\n3. Logging in...")
            if not self.login(demo_username, demo_password):
                print("⚠️  Login failed, trying admin...")
                if not self.login("admin", "admin123"):
                    print("❌ Could not login")
                    return
            
            # 4. Create session
            print("\n4. Creating new session...")
            session = self.create_session(
                name="Demo Session",
                vm_config={"cpu": 2, "memory": 4096},
                session_password="demo123",
                is_public=True,
                max_users=3
            )
            
            if not session:
                print("❌ Failed to create session")
                return
                
            session_id = session["session"]["id"]
            self.session_id = session_id
            
            # Wait a bit
            import time
            print("\n⏳ Waiting for setup...")
            time.sleep(2)
            
            # 5. Show how to join
            print("\n5. Joining session (simulating another user)...")
            print("   ⚠️  To join this session from another client:")
            print(f"      python client.py --join {session_id} --password demo123")
            
            # 6. Send message
            print("\n6. Sending chat message...")
            self.send_message(session_id, "Hello from the demo! This is a test message.")
            
            # Wait for response
            time.sleep(3)
            
            # 7. Get session users
            print("\n7. Getting session users...")
            users = self.get_session_users(session_id)
            if users:
                print(f"   Session has {len(users)} users:")
                for user in users:
                    print(f"     • {user['username']} ({user.get('access_level', 'unknown')})")
            
            # 8. System info
            print("\n8. System statistics...")
            self.print_system_info()
            
            print("\n" + "="*60)
            print("🎉 AUTHENTICATION DEMONSTRATION COMPLETED!")
            print(f"📋 Created session ID: {session_id}")
            print(f"🔑 Token stored for future use")
            print("="*60)
            
            # Save session info to file
            with open("demo_session.txt", "w") as f:
                f.write(f"Session ID: {session_id}\n")
                f.write(f"Session Password: demo123\n")
                f.write(f"Username: {demo_username}\n")
                f.write(f"Access Token: {self.access_token}\n")
            print("💾 Session info saved to demo_session.txt")
            
        except KeyboardInterrupt:
            print("\n⏹️  Demonstration interrupted by user")
        except Exception as e:
            print(f"❌ Demonstration error: {e}")
    
    # ============== INTERACTIVE MODE ==============
    async def run_interactive(self):
        """Interactive client mode with authentication
        
        Example:
            >>> import asyncio
            >>> client = ComputerUseAgentClient()
            >>> asyncio.run(client.run_interactive())
            🤖 COMPUTER USE AGENT - INTERACTIVE CLIENT
            ============================================================
            
            🔐 AUTHENTICATION MENU:
              1. Login
              2. Register
              3. Check current user
              4. Logout
            
            📋 MAIN MENU (requires login):
              5. Create new session
              6. Join existing session
              7. List sessions
              8. Send message
              9. View chat history
              10. VNC information
              11. Stream updates
              12. Connect WebSocket
              13. View activities
              14. System information
              15. Run demo
              0. Exit
            
            🔘 Choose an option: 1
            👤 Username: john_doe
            🔐 Password: 
            ✅ Successfully logged in as john_doe
        """
        print("🤖 COMPUTER USE AGENT - INTERACTIVE CLIENT")
        print("="*60)
        
        while True:
            print("\n🔐 AUTHENTICATION MENU:")
            print("  1. Login")
            print("  2. Register")
            print("  3. Check current user")
            print("  4. Logout")
            
            print("\n📋 MAIN MENU (requires login):")
            print("  5. Create new session")
            print("  6. Join existing session")
            print("  7. List sessions")
            print("  8. Send message")
            print("  9. View chat history")
            print("  10. VNC information")
            print("  11. Stream updates")
            print("  12. Connect WebSocket")
            print("  13. View activities")
            print("  14. System information")
            print("  15. Run demo")
            print("  0. Exit")
            
            choice = input("\n🔘 Choose an option: ").strip()
            
            if choice == "0":
                print("👋 Goodbye!")
                break
                
            elif choice == "1":
                username = input("👤 Username: ")
                password = getpass.getpass("🔐 Password: ")
                self.login(username, password)
                
            elif choice == "2":
                username = input("👤 Username: ")
                password = getpass.getpass("🔐 Password: ")
                email = input("📧 Email (optional): ")
                self.register(username, password, email if email else None)
                
            elif choice == "3":
                user = self.get_current_user()
                if user:
                    print(f"✅ Currently logged in as: {user['username']}")
                    print(f"📧 Email: {user.get('email', 'Not provided')}")
                    print(f"🆔 User ID: {user['id']}")
                else:
                    print("⚠️  Not logged in")
                    
            elif choice == "4":
                self.logout()
                
            elif choice == "5":
                if not self.is_authenticated():
                    print("❌ Please login first")
                    continue
                
                name = input("📝 Session name (optional): ")
                password = input("🔐 Session password (optional, auto-generated if empty): ")
                is_public = input("🌐 Public session? (y/N): ").lower() == 'y'
                max_users = input("👥 Max users (default 1): ")
                
                vm_config = {}
                vm_cpu = input("💻 CPU cores (optional): ")
                vm_memory = input("🧠 Memory MB (optional): ")
                
                if vm_cpu:
                    vm_config['cpu'] = int(vm_cpu)
                if vm_memory:
                    vm_config['memory'] = int(vm_memory)
                
                try:
                    max_users_int = int(max_users) if max_users else 1
                except:
                    max_users_int = 1
                
                self.create_session(
                    name=name if name else None,
                    vm_config=vm_config if vm_config else None,
                    session_password=password if password else None,
                    is_public=is_public,
                    max_users=max_users_int
                )
                
            elif choice == "6":
                if not self.is_authenticated():
                    print("❌ Please login first")
                    continue
                
                session_id = input("🔗 Session ID: ")
                password = getpass.getpass("🔐 Session Password: ")
                self.join_session(session_id, password)
                
            elif choice == "7":
                public_only = not self.is_authenticated()
                if public_only:
                    print("⚠️  Showing only public sessions (login to see private ones)")
                
                sessions = self.list_sessions(public_only)
                print(f"\n📋 Found {len(sessions)} sessions:")
                
                for i, sess in enumerate(sessions, 1):
                    print(f"\n{i}. {sess.get('name', 'Unnamed')}")
                    print(f"   ID: {sess['id']}")
                    print(f"   Status: {sess['status']}")
                    print(f"   Owner: {sess.get('username', 'Unknown')}")
                    print(f"   Users: {sess.get('current_users', 0)}/{sess.get('max_users', 1)}")
                    print(f"   Public: {'Yes' if sess.get('is_public') else 'No'}")
                    print(f"   Created: {sess['created_at']}")
                    
            elif choice == "8":
                if not self.is_authenticated():
                    print("❌ Please login first")
                    continue
                
                if not self.session_id:
                    self.session_id = input("🔗 Session ID: ")
                
                message = input("💬 Message: ")
                self.send_message(self.session_id, message)
                
            elif choice == "9":
                if not self.is_authenticated():
                    print("❌ Please login first")
                    continue
                
                if not self.session_id:
                    self.session_id = input("🔗 Session ID: ")
                
                self.print_chat_history(self.session_id)
                
            elif choice == "10":
                if not self.is_authenticated():
                    print("❌ Please login first")
                    continue
                
                if not self.session_id:
                    self.session_id = input("🔗 Session ID: ")
                
                self.print_vnc_info(self.session_id)
                
            elif choice == "11":
                if not self.is_authenticated():
                    print("❌ Please login first")
                    continue
                
                if not self.session_id:
                    self.session_id = input("🔗 Session ID: ")
                
                # Run in background thread
                import threading
                stream_thread = threading.Thread(
                    target=self.stream_session_updates,
                    args=(self.session_id,)
                )
                stream_thread.daemon = True
                stream_thread.start()
                print("📡 Streaming started in background...")
                
            elif choice == "12":
                if not self.is_authenticated():
                    print("❌ Please login first")
                    continue
                
                if not self.session_id:
                    self.session_id = input("🔗 Session ID: ")
                
                await self.connect_websocket(self.session_id)
                
            elif choice == "13":
                if not self.is_authenticated():
                    print("❌ Please login first")
                    continue
                
                if not self.session_id:
                    self.session_id = input("🔗 Session ID: ")
                
                self.print_activities(self.session_id)
                
            elif choice == "14":
                self.print_system_info()
                
            elif choice == "15":
                self.run_auth_demo()
                
            else:
                print("❌ Invalid option")

# ============== COMMAND LINE INTERFACE ==============
def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Client for Computer Use Agent with Authentication")
    parser.add_argument("--url", default="http://localhost:8000", 
                       help="Server URL (default: http://localhost:8000)")
    
    # Authentication commands
    parser.add_argument("--login", action="store_true", help="Login user")
    parser.add_argument("--register", action="store_true", help="Register new user")
    parser.add_argument("--logout", action="store_true", help="Logout current user")
    
    # Session commands
    parser.add_argument("--create", help="Create new session")
    parser.add_argument("--join", help="Join existing session with ID")
    parser.add_argument("--password", help="Password for joining session")
    parser.add_argument("--list", action="store_true", help="List sessions")
    parser.add_argument("--public", action="store_true", help="List only public sessions")
    parser.add_argument("--session", help="Session ID for operations")
    
    # Chat commands
    parser.add_argument("--message", help="Message to send (requires --session)")
    parser.add_argument("--history", action="store_true", 
                       help="View chat history (requires --session)")
    
    # Other commands
    parser.add_argument("--vnc", action="store_true", 
                       help="View VNC info (requires --session)")
    parser.add_argument("--stream", action="store_true", 
                       help="Start SSE stream (requires --session)")
    parser.add_argument("--websocket", action="store_true", 
                       help="Connect via WebSocket (requires --session)")
    parser.add_argument("--activities", action="store_true",
                       help="View session activities (requires --session)")
    parser.add_argument("--health", action="store_true", help="Check system health")
    parser.add_argument("--stats", action="store_true", help="Get system statistics")
    parser.add_argument("--demo", action="store_true", help="Run complete demonstration")
    parser.add_argument("--examples", action="store_true", help="Show usage examples")
    
    args = parser.parse_args()
    
    # Show examples if requested
    if args.examples:
        print("Usage Examples:")
        print("=" * 60)
        print("\n1. Register new user:")
        print("   python client.py --register")
        print("\n2. Login:")
        print("   python client.py --login")
        print("\n3. Create session:")
        print("   python client.py --create 'My Session'")
        print("\n4. Join session:")
        print("   python client.py --join SESSION_ID --password SESSION_PASSWORD")
        print("\n5. Send message:")
        print("   python client.py --session SESSION_ID --message 'Hello'")
        print("\n6. Interactive mode:")
        print("   python client.py")
        return 0
    
    client = ComputerUseAgentClient(base_url=args.url)
    
    # Try to load token from file if exists
    token_file = "auth_token.txt"
    if os.path.exists(token_file):
        try:
            with open(token_file, "r") as f:
                token_data = json.load(f)
                client.access_token = token_data.get("access_token")
                client.user_info = token_data.get("user_info")
                if client.access_token and client.user_info:
                    print(f"🔑 Loaded saved session for {client.user_info['username']}")
        except:
            pass
    
    try:
        # Handle authentication commands
        if args.register:
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            email = input("Email (optional): ")
            client.register(username, password, email if email else None)
            return
        
        if args.login:
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            if client.login(username, password):
                # Save token to file
                if client.access_token and client.user_info:
                    with open(token_file, "w") as f:
                        json.dump({
                            "access_token": client.access_token,
                            "user_info": client.user_info
                        }, f)
                    print(f"💾 Session saved to {token_file}")
            return
        
        if args.logout:
            client.logout()
            if os.path.exists(token_file):
                os.remove(token_file)
                print(f"🗑️  Removed saved session")
            return
        
        # Handle other commands
        if args.health:
            health = client.health_check()
            if health:
                print(f"✅ System {health.get('status', 'unknown')}")
                print(f"🕐 Last check: {health.get('timestamp', 'N/A')}")
                print(f"🗄️  Total sessions: {health.get('total_sessions', 0)}")
            else:
                print("❌ System not responding")
            return
        
        if args.demo:
            client.run_auth_demo()
            return
        
        # Commands that don't require authentication
        if args.list:
            sessions = client.list_sessions(args.public)
            print(f"\n📋 Found {len(sessions)} sessions:")
            for sess in sessions:
                print(f"\n• {sess.get('name', 'Unnamed')}")
                print(f"  ID: {sess['id']}")
                print(f"  Status: {sess['status']}")
                print(f"  Owner: {sess.get('username', 'Unknown')}")
                print(f"  Public: {'Yes' if sess.get('is_public') else 'No'}")
            return
        
        # Commands that require session ID
        if args.session:
            client.session_id = args.session
            
            if args.message:
                if not client.is_authenticated():
                    print("❌ You must be logged in to send messages")
                    if input("Login now? (y/N): ").lower() == 'y':
                        username = input("Username: ")
                        password = getpass.getpass("Password: ")
                        if client.login(username, password):
                            client.send_message(args.session, args.message)
                    return
                client.send_message(args.session, args.message)
                
            elif args.history:
                if not client.is_authenticated():
                    print("❌ You must be logged in to view chat history")
                    if input("Login now? (y/N): ").lower() == 'y':
                        username = input("Username: ")
                        password = getpass.getpass("Password: ")
                        if client.login(username, password):
                            client.print_chat_history(args.session)
                    return
                client.print_chat_history(args.session)
                
            elif args.vnc:
                if not client.is_authenticated():
                    print("❌ You must be logged in to view VNC info")
                    if input("Login now? (y/N): ").lower() == 'y':
                        username = input("Username: ")
                        password = getpass.getpass("Password: ")
                        if client.login(username, password):
                            client.print_vnc_info(args.session)
                    return
                client.print_vnc_info(args.session)
                
            elif args.stream:
                if not client.is_authenticated():
                    print("❌ You must be logged in to stream updates")
                    if input("Login now? (y/N): ").lower() == 'y':
                        username = input("Username: ")
                        password = getpass.getpass("Password: ")
                        if client.login(username, password):
                            client.stream_session_updates(args.session)
                    return
                client.stream_session_updates(args.session)
                
            elif args.websocket:
                if not client.is_authenticated():
                    print("❌ You must be logged in to use WebSocket")
                    if input("Login now? (y/N): ").lower() == 'y':
                        username = input("Username: ")
                        password = getpass.getpass("Password: ")
                        if client.login(username, password):
                            asyncio.run(client.connect_websocket(args.session))
                    return
                asyncio.run(client.connect_websocket(args.session))
                
            elif args.activities:
                if not client.is_authenticated():
                    print("❌ You must be logged in to view activities")
                    if input("Login now? (y/N): ").lower() == 'y':
                        username = input("Username: ")
                        password = getpass.getpass("Password: ")
                        if client.login(username, password):
                            client.print_activities(args.session)
                    return
                client.print_activities(args.session)
                
            else:
                # Show session information
                if not client.is_authenticated():
                    print("⚠️  Not logged in - limited information")
                    print(f"Session ID: {args.session}")
                    print("💡 Login to view full details")
                    return
                
                session = client.get_session(args.session)
                if session:
                    print(f"\n📊 Session: {session.get('name', 'Unnamed')}")
                    print(f"🆔 ID: {session['id']}")
                    print(f"📈 Status: {session['status']}")
                    print(f"👤 Owner: {session.get('username', 'Unknown')}")
                    print(f"👥 Users: {session.get('current_users', 0)}/{session.get('max_users', 1)}")
                    print(f"🌐 Public: {'Yes' if session.get('is_public') else 'No'}")
                    print(f"📅 Created: {session['created_at']}")
                    print(f"🔄 Updated: {session['updated_at']}")
                    
                    # Get connected users
                    connected = client.get_connected_users(args.session)
                    if connected:
                        print(f"\n🔗 Currently connected ({len(connected)}):")
                        for user in connected:
                            print(f"  • {user.get('username', 'Unknown')}")
                else:
                    print("❌ Session not found or no access")
            
            return
        
        # Session creation
        if args.create:
            if not client.is_authenticated():
                print("❌ You must be logged in to create a session")
                if input("Login now? (y/N): ").lower() == 'y':
                    username = input("Username: ")
                    password = getpass.getpass("Password: ")
                    if client.login(username, password):
                        client.create_session(name=args.create)
                return
            
            session_password = input("Session password (optional, press Enter to auto-generate): ")
            is_public = input("Public session? (y/N): ").lower() == 'y'
            max_users = input("Max users (default 1): ")
            
            try:
                max_users_int = int(max_users) if max_users else 1
            except:
                max_users_int = 1
            
            client.create_session(
                name=args.create,
                session_password=session_password if session_password else None,
                is_public=is_public,
                max_users=max_users_int
            )
            return
        
        # Join session
        if args.join:
            if not client.is_authenticated():
                print("❌ You must be logged in to join a session")
                if input("Login now? (y/N): ").lower() == 'y':
                    username = input("Username: ")
                    password = getpass.getpass("Password: ")
                    if client.login(username, password):
                        session_password = args.password or getpass.getpass("Session password: ")
                        client.join_session(args.join, session_password)
                return
            
            session_password = args.password or getpass.getpass("Session password: ")
            client.join_session(args.join, session_password)
            return
        
        # Statistics
        if args.stats:
            if not client.is_authenticated():
                print("❌ You must be logged in to view statistics")
                return
            
            stats = client.get_stats()
            if stats:
                print(f"\n📊 Your statistics:")
                print(f"   • Your sessions: {stats.get('user_sessions', 0)}")
                print(f"   • Total system sessions: {stats.get('total_sessions_all', 0)}")
                
                if 'status_counts' in stats:
                    print(f"\n📈 Your session statuses:")
                    for status, count in stats['status_counts'].items():
                        print(f"   • {status}: {count}")
            return
        
        # Interactive mode (default)
        asyncio.run(client.run_interactive())
            
    except KeyboardInterrupt:
        print("\n👋 Interrupted by user")
        return 0
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    # Check dependencies
    try:
        import requests
        import websockets
        import bcrypt
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        print("📦 Install with: pip install requests websockets bcrypt")
        sys.exit(1)
    
    sys.exit(main())
