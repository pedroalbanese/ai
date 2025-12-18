"""
COMPUTER USE AGENT BACKEND - SINGLE FILE SOLUTION
FastAPI backend for computer use agent session management
WITH SESSION PASSWORD AUTHENTICATION - PYDANTIC V2 COMPATIBLE
"""
import asyncio
import json
import uuid
import sqlite3
import bcrypt
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks, status, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator, ConfigDict
import websockets
import requests

# ============== SECURITY ==============
security = HTTPBearer()

# ============== OLLAMA AI INTEGRATION ==============

class OllamaAI:
    """Integration with Ollama via HTTP (Docker-friendly)"""

    def __init__(self):
        self.base_url = "http://localhost:11434"
        self.models = []
        self.available = self._check_ollama_service()  # <--- available attribute

    def _check_ollama_service(self) -> bool:
        """Checks if the Ollama service is running"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            if response.status_code == 200:
                self.models = response.json().get("models", [])
                print("✅ Ollama service is running")
                if self.models:
                    print(f"📚 Available models: {[m['name'] for m in self.models]}")
                return True
        except Exception as e:
            print(f"⚠️ Ollama is inaccessible: {e}")
        return False

    async def get_response(self, user_message: str) -> str:
        """Gets a response from Ollama via HTTP"""
        if not self.available:
            return self._get_fallback_response(user_message)

        models_to_try = ["tinyllama:latest"]
        
        for model in models_to_try:
            try:
                response = requests.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": model,
                        "prompt": user_message,
                        "stream": False
                    },
                    timeout=600
                )

                if response.status_code == 200:
                    return response.json().get("response", "").strip()

            except Exception as e:
                print(f"⚠️ Model {model} failed: {e}")

        return self._get_fallback_response(user_message)

    def _get_fallback_response(self, user_message: str) -> str:
        """Fallback response when Ollama is not available"""
        message_lower = user_message.lower()

        if any(w in message_lower for w in ['olá', 'oi', 'hello', 'hi', 'bom dia']):
            return "Hello! I am your computer assistant. How can I help you today?"

        if any(w in message_lower for w in ['hora', 'time', 'horas']):
            return f"The current time is {datetime.now().strftime('%H:%M:%S')}"

        if any(w in message_lower for w in ['data', 'date', 'dia', 'hoje']):
            return f"Today is {datetime.now().strftime('%A, %d %B %Y')}"

        return f"I understand that you asked: '{user_message}'. I can help you with computer tasks."


ollama_ai = OllamaAI()

# ============== DATABASE SETUP ==============
def init_database():
    """Initialize SQLite database with authentication"""
    conn = sqlite3.connect('sessions.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Users table for authentication
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    ''')
    
    # Sessions table with password authentication
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT,
        status TEXT DEFAULT 'pending',
        vm_config TEXT,
        agent_config TEXT,
        vnc_port INTEGER,
        vnc_password TEXT,
        session_password TEXT NOT NULL,  -- Hash of session password
        is_public BOOLEAN DEFAULT FALSE,
        max_users INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Session access table (for shared sessions)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS session_access (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        access_level TEXT DEFAULT 'viewer',  -- viewer, editor, admin
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES sessions (id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(session_id, user_id)
    )
    ''')
    
    # Chat messages table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS chat_messages (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES sessions (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Activities table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS session_activities (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        activity_type TEXT NOT NULL,
        description TEXT,
        metadata TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES sessions (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create default admin user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        admin_id = str(uuid.uuid4())
        # Default password: admin123
        password_hash = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
            INSERT INTO users (id, username, password_hash, email)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, 'admin', password_hash, 'admin@example.com'))
    
    # Create AI assistant user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'ai_assistant'")
    if cursor.fetchone()[0] == 0:
        ai_id = str(uuid.uuid4())
        ai_password_hash = bcrypt.hashpw(str(uuid.uuid4()).encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
            INSERT INTO users (id, username, password_hash, email)
            VALUES (?, ?, ?, ?)
        ''', (ai_id, 'ai_assistant', ai_password_hash, 'ai@example.com'))
    
    conn.commit()
    return conn

# Initialize database
DB_CONN = init_database()

# ============== PASSWORD HELPERS ==============
def hash_password(password: str) -> str:
    """Hash a password for storing"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a stored password against one provided by user"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# ============== MODELS ==============
class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)

class UserLogin(BaseModel):
    username: str
    password: str
    
    model_config = ConfigDict(from_attributes=True)

class UserResponse(BaseModel):
    id: str
    username: str
    email: Optional[str]
    created_at: str
    
    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str
    username: str
    
    model_config = ConfigDict(from_attributes=True)

class SessionCreate(BaseModel):
    name: Optional[str] = None
    vm_config: Optional[Dict[str, Any]] = {}
    agent_config: Optional[Dict[str, Any]] = {}
    session_password: Optional[str] = None  # If not provided, will be generated
    is_public: bool = False
    max_users: int = 1
    
    model_config = ConfigDict(from_attributes=True)
    
    @field_validator('session_password')
    @classmethod
    def validate_password(cls, v):
        if v is not None and len(v) < 4:
            raise ValueError('Password must be at least 4 characters')
        return v

class SessionJoin(BaseModel):
    session_id: str
    session_password: str
    
    model_config = ConfigDict(from_attributes=True)

class SessionUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    vm_config: Optional[Dict[str, Any]] = None
    is_public: Optional[bool] = None
    max_users: Optional[int] = None
    
    model_config = ConfigDict(from_attributes=True)

class SessionInDB(BaseModel):
    id: str
    user_id: str
    username: str
    name: Optional[str]
    status: str
    vm_config: Optional[Dict[str, Any]]
    agent_config: Optional[Dict[str, Any]]
    vnc_port: Optional[int]
    vnc_password: Optional[str]
    is_public: bool
    max_users: int
    current_users: int
    created_at: str
    updated_at: str
    expires_at: Optional[str]
    
    model_config = ConfigDict(from_attributes=True)

class SessionResponse(BaseModel):
    session: SessionInDB
    session_password: Optional[str] = None  # Only returned on creation
    vnc_url: Optional[str] = None
    websocket_url: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)

class ChatMessageCreate(BaseModel):
    session_id: str
    content: str
    
    model_config = ConfigDict(from_attributes=True)

class ChatMessageInDB(BaseModel):
    id: str
    session_id: str
    user_id: str
    username: str
    role: str
    content: str
    created_at: str
    
    model_config = ConfigDict(from_attributes=True)

class VNCConnectRequest(BaseModel):
    password: str
    
    model_config = ConfigDict(from_attributes=True)

# ============== AUTHENTICATION ==============
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from token"""
    token = credentials.credentials
    cursor = DB_CONN.cursor()
    
    cursor.execute('''
        SELECT id, username, email, password_hash FROM users 
        WHERE id = ? OR username = ?
    ''', (token, token))
    
    row = cursor.fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    columns = [desc[0] for desc in cursor.description]
    user = dict(zip(columns, row))
    
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"]
    }

async def verify_session_access(session_id: str, user: Dict, required_access: str = "viewer") -> bool:
    """Verify if user has access to session"""
    cursor = DB_CONN.cursor()
    
    # Get session
    cursor.execute('SELECT user_id, is_public FROM sessions WHERE id = ?', (session_id,))
    session_row = cursor.fetchone()
    
    if not session_row:
        return False
    
    session_user_id, is_public = session_row
    
    # Owner has full access
    if session_user_id == user["id"]:
        return True
    
    # Check session access table
    cursor.execute('''
        SELECT access_level FROM session_access 
        WHERE session_id = ? AND user_id = ?
    ''', (session_id, user["id"]))
    
    access_row = cursor.fetchone()
    if access_row:
        access_level = access_row[0]
        # Check if access level is sufficient
        access_hierarchy = {"viewer": 1, "editor": 2, "admin": 3}
        required_level = access_hierarchy.get(required_access, 0)
        user_level = access_hierarchy.get(access_level, 0)
        return user_level >= required_level
    
    # Public sessions allow view access
    if is_public and required_access == "viewer":
        return True
    
    return False

# ============== DATABASE SERVICES ==============
class DatabaseService:
    
    # ============== USER METHODS ==============
    @staticmethod
    def create_user(user_data: UserCreate) -> Dict:
        """Create a new user"""
        cursor = DB_CONN.cursor()
        
        # Check if username exists
        cursor.execute('SELECT id FROM users WHERE username = ?', (user_data.username,))
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        
        user_id = str(uuid.uuid4())
        password_hash = hash_password(user_data.password)
        
        cursor.execute('''
            INSERT INTO users (id, username, password_hash, email)
            VALUES (?, ?, ?, ?)
        ''', (
            user_id,
            user_data.username,
            password_hash,
            user_data.email
        ))
        
        DB_CONN.commit()
        
        return DatabaseService.get_user(user_id)
    
    @staticmethod
    def get_user(user_id_or_username: str) -> Optional[Dict]:
        """Get user by ID or username"""
        cursor = DB_CONN.cursor()
        cursor.execute('''
            SELECT id, username, email, password_hash, created_at, last_login 
            FROM users WHERE id = ? OR username = ?
        ''', (user_id_or_username, user_id_or_username))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        columns = [desc[0] for desc in cursor.description]
        user = dict(zip(columns, row))
        
        # Don't return password hash
        user.pop('password_hash', None)
        return user
    
    @staticmethod
    def authenticate_user(username: str, password: str) -> Optional[Dict]:
        """Authenticate user"""
        cursor = DB_CONN.cursor()
        cursor.execute('''
            SELECT id, username, email, password_hash FROM users 
            WHERE username = ?
        ''', (username,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        columns = [desc[0] for desc in cursor.description]
        user = dict(zip(columns, row))
        
        # Verify password
        if not verify_password(password, user['password_hash']):
            return None
        
        # Update last login
        cursor.execute('''
            UPDATE users SET last_login = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (user['id'],))
        DB_CONN.commit()
        
        # Don't return password hash
        user.pop('password_hash', None)
        return user
    
    # ============== SESSION METHODS ==============
    @staticmethod
    def create_session(session_data: SessionCreate, user_id: str, username: str) -> Dict:
        """Create a new session"""
        session_id = str(uuid.uuid4())
        cursor = DB_CONN.cursor()
        
        # Generate session password if not provided
        session_password = session_data.session_password or str(uuid.uuid4())[:8]
        session_password_hash = hash_password(session_password)
        
        cursor.execute('''
            INSERT INTO sessions (id, user_id, name, status, vm_config, agent_config, session_password, is_public, max_users)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            user_id,
            session_data.name,
            'pending',
            json.dumps(session_data.vm_config or {}),
            json.dumps(session_data.agent_config or {}),
            session_password_hash,
            session_data.is_public,
            session_data.max_users
        ))
        
        # Add creator as admin access
        access_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO session_access (id, session_id, user_id, access_level)
            VALUES (?, ?, ?, ?)
        ''', (access_id, session_id, user_id, 'admin'))
        
        DB_CONN.commit()
        
        # Record activity
        DatabaseService.record_activity(
            session_id=session_id,
            user_id=user_id,
            activity_type="session_created",
            description=f"Session '{session_data.name or 'Unnamed'}' created"
        )
        
        session = DatabaseService.get_session(session_id)
        session['session_password'] = session_password  # Return plain password only on creation
        return session
    
    @staticmethod
    def get_session(session_id: str) -> Optional[Dict]:
        """Get session by ID"""
        cursor = DB_CONN.cursor()
        cursor.execute('''
            SELECT s.*, u.username, 
                   (SELECT COUNT(*) FROM session_access WHERE session_id = s.id) as current_users
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ?
        ''', (session_id,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        columns = [desc[0] for desc in cursor.description]
        session = dict(zip(columns, row))
        
        # Parse JSON fields
        for field in ['vm_config', 'agent_config']:
            if session.get(field):
                session[field] = json.loads(session[field])
            else:
                session[field] = {}
        
        # Don't return password hash
        session.pop('session_password', None)
        return session
    
    @staticmethod
    def join_session(session_id: str, session_password: str, user_id: str, username: str) -> bool:
        """Join a session with password"""
        cursor = DB_CONN.cursor()
        
        # Get session with password hash
        cursor.execute('SELECT session_password, is_public, max_users FROM sessions WHERE id = ?', (session_id,))
        session_row = cursor.fetchone()
        
        if not session_row:
            return False
        
        session_password_hash, is_public, max_users = session_row
        
        # Verify password
        if not verify_password(session_password, session_password_hash):
            return False
        
        # Check if user already has access
        cursor.execute('SELECT id FROM session_access WHERE session_id = ? AND user_id = ?', (session_id, user_id))
        if cursor.fetchone():
            return True  # Already joined
        
        # Check max users
        cursor.execute('SELECT COUNT(*) FROM session_access WHERE session_id = ?', (session_id,))
        current_users = cursor.fetchone()[0]
        
        if current_users >= max_users:
            return False
        
        # Add user access
        access_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO session_access (id, session_id, user_id, access_level)
            VALUES (?, ?, ?, ?)
        ''', (access_id, session_id, user_id, 'viewer'))
        
        DB_CONN.commit()
        
        # Record activity
        DatabaseService.record_activity(
            session_id=session_id,
            user_id=user_id,
            activity_type="user_joined",
            description=f"User '{username}' joined the session"
        )
        
        return True
    
    @staticmethod
    def list_sessions(user_id: Optional[str] = None, public_only: bool = False, limit: int = 100) -> List[Dict]:
        """List all sessions"""
        cursor = DB_CONN.cursor()
        
        if user_id:
            # Get sessions user has access to
            cursor.execute('''
                SELECT s.*, u.username,
                       (SELECT COUNT(*) FROM session_access WHERE session_id = s.id) as current_users
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                JOIN session_access sa ON s.id = sa.session_id
                WHERE sa.user_id = ?
                ORDER BY s.created_at DESC 
                LIMIT ?
            ''', (user_id, limit))
        elif public_only:
            # Get only public sessions
            cursor.execute('''
                SELECT s.*, u.username,
                       (SELECT COUNT(*) FROM session_access WHERE session_id = s.id) as current_users
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.is_public = 1
                ORDER BY s.created_at DESC 
                LIMIT ?
            ''', (limit,))
        else:
            # Get all sessions (admin only)
            cursor.execute('''
                SELECT s.*, u.username,
                       (SELECT COUNT(*) FROM session_access WHERE session_id = s.id) as current_users
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                ORDER BY s.created_at DESC 
                LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        
        sessions = []
        for row in rows:
            session = dict(zip(columns, row))
            # Parse JSON fields
            for field in ['vm_config', 'agent_config']:
                if session.get(field):
                    session[field] = json.loads(session[field])
                else:
                    session[field] = {}
            # Don't return password hash
            session.pop('session_password', None)
            sessions.append(session)
        
        return sessions
    
    @staticmethod
    def update_session(session_id: str, update_data: Dict, user_id: str) -> Optional[Dict]:
        """Update session - only owner can update"""
        session = DatabaseService.get_session(session_id)
        if not session:
            return None
        
        # Check if user is owner
        if session['user_id'] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only session owner can update session"
            )
        
        cursor = DB_CONN.cursor()
        
        # Build update query
        set_clauses = []
        params = []
        
        for key, value in update_data.items():
            if value is not None:
                if key in ['vm_config', 'agent_config']:
                    set_clauses.append(f"{key} = ?")
                    params.append(json.dumps(value))
                else:
                    set_clauses.append(f"{key} = ?")
                    params.append(value)
        
        if not set_clauses:
            return session
        
        set_clauses.append("updated_at = CURRENT_TIMESTAMP")
        
        query = f"UPDATE sessions SET {', '.join(set_clauses)} WHERE id = ?"
        params.append(session_id)
        
        cursor.execute(query, params)
        DB_CONN.commit()
        
        # Record activity
        DatabaseService.record_activity(
            session_id=session_id,
            user_id=user_id,
            activity_type="session_updated",
            description=f"Session updated"
        )
        
        return DatabaseService.get_session(session_id)
    
    @staticmethod
    def delete_session(session_id: str, user_id: str) -> bool:
        """Delete session - only owner can delete"""
        session = DatabaseService.get_session(session_id)
        if not session:
            return False
        
        # Check if user is owner
        if session['user_id'] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only session owner can delete session"
            )
        
        cursor = DB_CONN.cursor()
        
        # Delete related records first
        cursor.execute('DELETE FROM chat_messages WHERE session_id = ?', (session_id,))
        cursor.execute('DELETE FROM session_activities WHERE session_id = ?', (session_id,))
        cursor.execute('DELETE FROM session_access WHERE session_id = ?', (session_id,))
        
        # Delete session
        cursor.execute('DELETE FROM sessions WHERE id = ?', (session_id,))
        
        DB_CONN.commit()
        
        # Record activity (in a log file or separate table)
        print(f"Session {session_id} deleted by user {user_id}")
        
        return True
    
    @staticmethod
    def get_session_users(session_id: str) -> List[Dict]:
        """Get all users who have access to a session"""
        cursor = DB_CONN.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email, sa.access_level, sa.created_at as joined_at
            FROM session_access sa
            JOIN users u ON sa.user_id = u.id
            WHERE sa.session_id = ?
            ORDER BY sa.created_at
        ''', (session_id,))
        
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        
        return [dict(zip(columns, row)) for row in rows]
    
    # ============== CHAT METHODS ==============
    @staticmethod
    def save_chat_message(session_id: str, user_id: str, role: str, content: str) -> Dict:
        """Save chat message - FIXED VERSION"""
        message_id = str(uuid.uuid4())
        cursor = DB_CONN.cursor()
        
        # Insert message
        cursor.execute('''
            INSERT INTO chat_messages (id, session_id, user_id, role, content)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            message_id,
            session_id,
            user_id,
            role,
            content
        ))
        
        DB_CONN.commit()
        
        # Get the saved message with username
        cursor.execute('''
            SELECT cm.*, COALESCE(u.username, 
                CASE WHEN cm.role = 'assistant' THEN 'AI Assistant' ELSE 'Unknown' END) as username
            FROM chat_messages cm
            LEFT JOIN users u ON cm.user_id = u.id
            WHERE cm.id = ?
        ''', (message_id,))
        
        row = cursor.fetchone()
        if row is None:
            # Fallback: create a basic message object
            return {
                "id": message_id,
                "session_id": session_id,
                "user_id": user_id,
                "username": "AI Assistant" if role == "assistant" else "Unknown",
                "role": role,
                "content": content,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        
        columns = [desc[0] for desc in cursor.description]
        message = dict(zip(columns, row))
        
        # Record activity
        DatabaseService.record_activity(
            session_id=session_id,
            user_id=user_id,
            activity_type="chat_message",
            description=f"New {role} message"
        )
        
        return message
    
    @staticmethod
    def get_chat_history(session_id: str, limit: int = 50) -> List[Dict]:
        """Get chat history for session - FIXED VERSION"""
        cursor = DB_CONN.cursor()
        cursor.execute('''
            SELECT cm.*, COALESCE(u.username, 
                CASE WHEN cm.role = 'assistant' THEN 'AI Assistant' ELSE 'Unknown' END) as username
            FROM chat_messages cm
            LEFT JOIN users u ON cm.user_id = u.id
            WHERE cm.session_id = ? 
            ORDER BY cm.created_at ASC 
            LIMIT ?
        ''', (session_id, limit))
        
        rows = cursor.fetchall()
        if not rows:
            return []
        
        columns = [desc[0] for desc in cursor.description]
        
        return [dict(zip(columns, row)) for row in rows]
    
    # ============== ACTIVITY METHODS ==============
    @staticmethod
    def record_activity(session_id: str, user_id: str, activity_type: str, description: str, metadata: Dict = None):
        """Record session activity"""
        activity_id = str(uuid.uuid4())
        cursor = DB_CONN.cursor()
        
        cursor.execute('''
            INSERT INTO session_activities (id, session_id, user_id, activity_type, description, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            activity_id,
            session_id,
            user_id,
            activity_type,
            description,
            json.dumps(metadata or {})
        ))
        
        DB_CONN.commit()
    
    @staticmethod
    def get_session_activities(session_id: str, limit: int = 20) -> List[Dict]:
        """Get session activities"""
        cursor = DB_CONN.cursor()
        cursor.execute('''
            SELECT sa.*, u.username
            FROM session_activities sa
            JOIN users u ON sa.user_id = u.id
            WHERE sa.session_id = ?
            ORDER BY sa.created_at DESC
            LIMIT ?
        ''', (session_id, limit))
        
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        
        return [dict(zip(columns, row)) for row in rows]

# ============== VIRTUAL MACHINE MANAGER ==============
class VMManager:
    """Mock VM manager for demonstration"""
    
    @staticmethod
    async def start_vm(session_id: str, vm_config: Dict) -> Dict:
        """Start a virtual machine (mock implementation)"""
        import random
        
        # Simulate VM startup delay
        await asyncio.sleep(2)
        
        # Generate VNC port and password
        vnc_port = random.randint(5901, 5999)
        vnc_password = str(uuid.uuid4())[:8]
        
        # Update session with VM info
        cursor = DB_CONN.cursor()
        cursor.execute('''
            UPDATE sessions 
            SET status = 'active', vnc_port = ?, vnc_password = ?
            WHERE id = ?
        ''', (vnc_port, vnc_password, session_id))
        DB_CONN.commit()
        
        # Record activity
        session = DatabaseService.get_session(session_id)
        if session:
            DatabaseService.record_activity(
                session_id=session_id,
                user_id=session['user_id'],
                activity_type="vm_started",
                description="Virtual machine started",
                metadata={"vnc_port": vnc_port}
            )
        
        return {
            "vnc_port": vnc_port,
            "vnc_password": vnc_password,
            "status": "running"
        }
    
    @staticmethod
    async def terminate_vm(session_id: str):
        """Terminate virtual machine"""
        await asyncio.sleep(1)
        
        cursor = DB_CONN.cursor()
        cursor.execute('UPDATE sessions SET status = "terminated" WHERE id = ?', (session_id,))
        DB_CONN.commit()
        
        session = DatabaseService.get_session(session_id)
        if session:
            DatabaseService.record_activity(
                session_id=session_id,
                user_id=session['user_id'],
                activity_type="vm_terminated",
                description="Virtual machine terminated"
            )

# ============== WEBSOCKET MANAGER WITH AUTH ==============
class WebSocketManager:
    """Manage WebSocket connections with authentication"""
    
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.connection_users: Dict[str, Dict[str, Any]] = {}  # websocket_id -> user_info
        self.connection_tasks: Dict[str, asyncio.Task] = {}
    
    async def connect(self, websocket: WebSocket, session_id: str, user: Dict):
        """Accept WebSocket connection with authentication"""
        await websocket.accept()
        
        if session_id not in self.active_connections:
            self.active_connections[session_id] = []
        
        self.active_connections[session_id].append(websocket)
        
        # Store user info
        websocket_id = id(websocket)
        self.connection_users[str(websocket_id)] = {
            "user_id": user["id"],
            "username": user["username"],
            "session_id": session_id
        }
        
        # Send welcome message
        await self.send_to_session(
            session_id,
            {
                "type": "connected",
                "user_id": user["id"],
                "username": user["username"],
                "message": f"{user['username']} connected to session",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
        
        DatabaseService.record_activity(
            session_id=session_id,
            user_id=user["id"],
            activity_type="websocket_connected",
            description=f"WebSocket connection established by {user['username']}"
        )
    
    async def disconnect(self, websocket: WebSocket, session_id: str):
        """Disconnect WebSocket"""
        websocket_id = id(websocket)
        
        if session_id in self.active_connections:
            if websocket in self.active_connections[session_id]:
                self.active_connections[session_id].remove(websocket)
            
            if not self.active_connections[session_id]:
                del self.active_connections[session_id]
        
        # Remove user info
        if str(websocket_id) in self.connection_users:
            user_info = self.connection_users[str(websocket_id)]
            
            # Notify others about disconnection
            await self.send_to_session(
                session_id,
                {
                    "type": "disconnected",
                    "user_id": user_info["user_id"],
                    "username": user_info["username"],
                    "message": f"{user_info['username']} disconnected",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
            
            del self.connection_users[str(websocket_id)]
    
    async def send_to_session(self, session_id: str, message: Dict):
        """Send message to all connections in a session"""
        if session_id in self.active_connections:
            disconnected = []
            for connection in self.active_connections[session_id]:
                try:
                    await connection.send_json(message)
                except:
                    disconnected.append(connection)
            
            # Remove disconnected clients
            for connection in disconnected:
                await self.disconnect(connection, session_id)
    
    async def send_to_user(self, session_id: str, user_id: str, message: Dict):
        """Send message to specific user in a session"""
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                websocket_id = id(connection)
                user_info = self.connection_users.get(str(websocket_id))
                if user_info and user_info["user_id"] == user_id:
                    try:
                        await connection.send_json(message)
                        return True
                    except:
                        pass
        return False
    
    async def broadcast_progress(self, session_id: str, progress: Dict):
        """Broadcast progress update"""
        message = {
            "type": "progress",
            "data": progress,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await self.send_to_session(session_id, message)
    
    async def broadcast_chat(self, session_id: str, message: Dict):
        """Broadcast chat message"""
        message["type"] = "chat"
        message["timestamp"] = datetime.now(timezone.utc).isoformat()
        await self.send_to_session(session_id, message)
    
    def get_connection_count(self, session_id: str) -> int:
        """Get number of connections for a session"""
        if session_id in self.active_connections:
            return len(self.active_connections[session_id])
        return 0
    
    def get_connected_users(self, session_id: str) -> List[Dict]:
        """Get list of connected users in a session"""
        connected_users = []
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                websocket_id = id(connection)
                user_info = self.connection_users.get(str(websocket_id))
                if user_info and user_info["session_id"] == session_id:
                    connected_users.append(user_info)
        return connected_users

# ============== VNC PROXY ==============
class VNCProxy:
    """Simple VNC WebSocket proxy"""
    
    @staticmethod
    async def proxy_websocket(client_ws: WebSocket, vnc_port: int, password: str):
        """Proxy WebSocket to VNC server (mock implementation)"""
        # In a real implementation, this would connect to a real VNC server
        # For demonstration, we'll simulate VNC connection
        
        await client_ws.accept()
        
        try:
            # Send VNC initialization
            await client_ws.send_json({
                "type": "vnc_init",
                "status": "connected",
                "port": vnc_port
            })
            
            # Simulate VNC frame updates
            while True:
                # Wait for client message
                try:
                    data = await client_ws.receive_json(timeout=1.0)
                    
                    if data.get("type") == "key_event":
                        # Simulate key press handling
                        await client_ws.send_json({
                            "type": "vnc_update",
                            "message": f"Key pressed: {data.get('key')}"
                        })
                    
                    elif data.get("type") == "mouse_event":
                        # Simulate mouse movement
                        await client_ws.send_json({
                            "type": "vnc_update",
                            "message": f"Mouse moved to ({data.get('x')}, {data.get('y')})"
                        })
                        
                except asyncio.TimeoutError:
                    # Send periodic frame updates
                    await client_ws.send_json({
                        "type": "vnc_frame",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "data": "mock_frame_data"
                    })
                    
        except WebSocketDisconnect:
            print(f"VNC WebSocket disconnected")
        except Exception as e:
            print(f"VNC proxy error: {e}")
            await client_ws.close()

# ============== AGENT SERVICE WITH OLLAMA ==============
class AgentService:
    """AI agent service using Ollama"""
    
    def __init__(self):
        self.ai = ollama_ai
    
    async def process_message(self, session_id: str, user_id: str, username: str, user_message: str) -> Dict:
        """Process user message with Ollama AI - FIXED VERSION"""
        # Generate AI response using Ollama
        ai_response = await self.ai.get_response(user_message)
        
        # Get AI assistant user ID
        cursor = DB_CONN.cursor()
        cursor.execute("SELECT id FROM users WHERE username = 'ai_assistant'")
        ai_user = cursor.fetchone()
        
        if not ai_user:
            # Fallback: use a dummy user ID for AI
            ai_user_id = "00000000-0000-0000-0000-000000000000"
        else:
            ai_user_id = ai_user[0]
        
        # Save agent response
        agent_message = DatabaseService.save_chat_message(
            session_id=session_id,
            user_id=ai_user_id,
            role="assistant",
            content=ai_response
        )
        
        # Record activity
        DatabaseService.record_activity(
            session_id=session_id,
            user_id=user_id,
            activity_type="agent_response",
            description=f"Agent responded to {username}'s message"
        )
        
        return agent_message

# ============== FASTAPI APP ==============
# Initialize managers
websocket_manager = WebSocketManager()
vm_manager = VMManager()
vnc_proxy = VNCProxy()
agent_service = AgentService()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager"""
    # Startup
    print("🚀 Computer Use Agent Backend starting...")
    print(f"🤖 AI: {'Ollama' if ollama_ai.available else 'Fallback (Simple AI)'}")
    print("🔐 Authentication: Enabled")
    print("👥 Multi-user sessions: Enabled")
    yield
    # Shutdown
    print("👋 Shutting down...")

# Create FastAPI app
app = FastAPI(
    title="Computer Use Agent Backend",
    description="Secure multi-user backend for computer use agent session management",
    version="2.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============== AUTHENTICATION ENDPOINTS ==============
@app.post("/api/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(user_create: UserCreate):
    """Register a new user"""
    try:
        user = DatabaseService.create_user(user_create)
        return UserResponse(**user)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to register user: {str(e)}"
        )

@app.post("/api/auth/login", response_model=Token)
async def login(user_login: UserLogin):
    """Login user"""
    user = DatabaseService.authenticate_user(user_login.username, user_login.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # In a real app, generate JWT token
    # For simplicity, we'll use user ID as token
    return Token(
        access_token=user["id"],
        token_type="bearer",
        user_id=user["id"],
        username=user["username"]
    )

@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: Dict = Depends(get_current_user)):
    """Get current user info"""
    return UserResponse(**current_user)

# ============== SESSION ENDPOINTS ==============
@app.post("/api/sessions", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
async def create_session(
    session_create: SessionCreate,
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(get_current_user)
):
    """Create a new session"""
    try:
        # Create session in database
        session_dict = DatabaseService.create_session(
            session_create, 
            current_user["id"], 
            current_user["username"]
        )
        
        if not session_dict:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create session"
            )
        
        # Get the generated password
        session_password = session_dict.pop('session_password', None)
        
        # Start VM in background
        background_tasks.add_task(
            vm_manager.start_vm,
            session_id=session_dict['id'],
            vm_config=session_dict.get('vm_config', {})
        )
        
        # Generate URLs
        base_url = "http://localhost:8000"
        vnc_url = f"{base_url}/api/sessions/{session_dict['id']}/vnc"
        websocket_url = f"ws://localhost:8000/api/sessions/{session_dict['id']}/ws"
        
        session_obj = SessionInDB(**session_dict)
        
        return SessionResponse(
            session=session_obj,
            session_password=session_password,
            vnc_url=vnc_url,
            websocket_url=websocket_url
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create session: {str(e)}"
        )

@app.post("/api/sessions/join", response_model=SessionInDB)
async def join_session(
    session_join: SessionJoin,
    current_user: Dict = Depends(get_current_user)
):
    """Join an existing session with password"""
    success = DatabaseService.join_session(
        session_join.session_id,
        session_join.session_password,
        current_user["id"],
        current_user["username"]
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session ID or password, or session is full"
        )
    
    session = DatabaseService.get_session(session_join.session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    return SessionInDB(**session)

@app.get("/api/sessions", response_model=List[SessionInDB])
async def list_sessions(
    current_user: Dict = Depends(get_current_user),
    public: bool = Query(False, description="Show only public sessions"),
    limit: int = Query(100, ge=1, le=1000)
):
    """List all sessions accessible to current user"""
    sessions = DatabaseService.list_sessions(current_user["id"], public, limit)
    return [SessionInDB(**session) for session in sessions]

@app.get("/api/sessions/public", response_model=List[SessionInDB])
async def list_public_sessions(limit: int = Query(50, ge=1, le=100)):
    """List public sessions (no authentication required)"""
    sessions = DatabaseService.list_sessions(None, True, limit)
    return [SessionInDB(**session) for session in sessions]

@app.get("/api/sessions/{session_id}", response_model=SessionInDB)
async def get_session(
    session_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Get session by ID (requires access)"""
    # Check if user has access
    if not await verify_session_access(session_id, current_user, "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this session"
        )
    
    session = DatabaseService.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    return SessionInDB(**session)

@app.put("/api/sessions/{session_id}", response_model=SessionInDB)
async def update_session(
    session_id: str, 
    session_update: SessionUpdate,
    current_user: Dict = Depends(get_current_user)
):
    """Update session (owner only)"""
    updated_session = DatabaseService.update_session(
        session_id, 
        session_update.dict(exclude_unset=True),
        current_user["id"]
    )
    
    if not updated_session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    return SessionInDB(**updated_session)

@app.delete("/api/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(
    session_id: str, 
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(get_current_user)
):
    """Delete session (owner only)"""
    success = DatabaseService.delete_session(session_id, current_user["id"])
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Terminate VM in background
    background_tasks.add_task(vm_manager.terminate_vm, session_id)

@app.get("/api/sessions/{session_id}/users", response_model=List[Dict])
async def get_session_users(
    session_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Get all users who have access to a session"""
    # Check if user has access
    if not await verify_session_access(session_id, current_user, "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this session"
        )
    
    users = DatabaseService.get_session_users(session_id)
    return users

@app.get("/api/sessions/{session_id}/connected", response_model=List[Dict])
async def get_connected_users(
    session_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Get users currently connected via WebSocket"""
    # Check if user has access
    if not await verify_session_access(session_id, current_user, "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this session"
        )
    
    connected_users = websocket_manager.get_connected_users(session_id)
    return connected_users

# ============== CHAT ENDPOINTS ==============
@app.post("/api/chat/messages", response_model=ChatMessageInDB)
async def send_message(
    message: ChatMessageCreate, 
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(get_current_user)
):
    """Send chat message"""
    # Check if user has access to session
    if not await verify_session_access(message.session_id, current_user, "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this session"
        )
    
    # Save user message
    saved_message = DatabaseService.save_chat_message(
        session_id=message.session_id,
        user_id=current_user["id"],
        role="user",
        content=message.content
    )
    
    # Process with agent in background
    background_tasks.add_task(
        agent_service.process_message,
        session_id=message.session_id,
        user_id=current_user["id"],
        username=current_user["username"],
        user_message=message.content
    )
    
    # Broadcast via WebSocket
    await websocket_manager.broadcast_chat(
        message.session_id,
        {
            "user_id": current_user["id"],
            "username": current_user["username"],
            "role": "user",
            "content": message.content,
            "message_id": saved_message['id']
        }
    )
    
    return ChatMessageInDB(**saved_message)

@app.get("/api/sessions/{session_id}/chat", response_model=List[ChatMessageInDB])
async def get_chat_history(
    session_id: str, 
    limit: int = Query(50, ge=1, le=1000),
    current_user: Dict = Depends(get_current_user)
):
    """Get chat history"""
    # Check if user has access to session
    if not await verify_session_access(session_id, current_user, "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this session"
        )
    
    messages = DatabaseService.get_chat_history(session_id, limit)
    return [ChatMessageInDB(**msg) for msg in messages]

# ============== STREAMING ENDPOINTS ==============
@app.get("/api/sessions/{session_id}/stream")
async def stream_session_updates(
    session_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Server-Sent Events (SSE) stream for session updates"""
    # Check if user has access to session
    if not await verify_session_access(session_id, current_user, "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this session"
        )
    
    session = DatabaseService.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    async def event_generator():
        """Generate SSE events"""
        # Send initial status
        yield f"data: {json.dumps({'type': 'connected', 'session': session, 'user': current_user})}\n\n"
        
        # Send connected users
        connected_users = websocket_manager.get_connected_users(session_id)
        yield f"data: {json.dumps({'type': 'users_update', 'users': connected_users})}\n\n"
        
        # Simulate progress updates
        progress_steps = [
            "Initializing VM...",
            "Allocating resources...",
            "Starting VNC server...",
            "Loading agent...",
            "Ready for commands"
        ]
        
        for i, step in enumerate(progress_steps):
            await asyncio.sleep(2)
            progress = {
                "type": "progress",
                "step": i + 1,
                "total": len(progress_steps),
                "message": step,
                "percentage": (i + 1) * 100 / len(progress_steps)
            }
            yield f"data: {json.dumps(progress)}\n\n"
            
            # Also broadcast via WebSocket
            await websocket_manager.broadcast_progress(session_id, progress)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

# ============== WEBSOCKET ENDPOINTS WITH AUTH ==============
@app.websocket("/api/sessions/{session_id}/ws")
async def session_websocket(
    websocket: WebSocket, 
    session_id: str,
    token: str = Query(...)
):
    """WebSocket for real-time updates with authentication"""
    # Authenticate user
    try:
        # Simple token validation - in real app, validate JWT
        user = DatabaseService.get_user(token)
        if not user:
            await websocket.close(code=1008, reason="Invalid token")
            return
    except:
        await websocket.close(code=1008, reason="Authentication required")
        return
    
    # Check session access
    if not await verify_session_access(session_id, user, "viewer"):
        await websocket.close(code=1008, reason="Access denied")
        return
    
    session = DatabaseService.get_session(session_id)
    if not session:
        await websocket.close(code=1008, reason="Session not found")
        return
    
    # Connect WebSocket
    await websocket_manager.connect(websocket, session_id, user)
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()
            
            if data.get("type") == "chat":
                # Handle chat message
                if not data.get("content"):
                    continue
                
                # Save message
                saved_message = DatabaseService.save_chat_message(
                    session_id=session_id,
                    user_id=user["id"],
                    role="user",
                    content=data.get("content", "")
                )
                
                # Broadcast to other connections
                await websocket_manager.broadcast_chat(
                    session_id,
                    {
                        "user_id": user["id"],
                        "username": user["username"],
                        "role": "user",
                        "content": data.get("content", ""),
                        "message_id": saved_message['id']
                    }
                )
                
                # Process with Ollama AI
                ai_response = await agent_service.process_message(
                    session_id=session_id,
                    user_id=user["id"],
                    username=user["username"],
                    user_message=data.get("content", "")
                )
                
                # Send AI response to user
                await websocket_manager.send_to_user(
                    session_id,
                    user["id"],
                    {
                        "type": "agent_response",
                        "role": "assistant",
                        "content": ai_response['content'],
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                )
                
                # Broadcast AI response to all connections
                await websocket_manager.broadcast_chat(
                    session_id,
                    {
                        "user_id": "system",
                        "username": "AI Assistant",
                        "role": "assistant",
                        "content": ai_response['content']
                    }
                )
                
            elif data.get("type") == "command":
                # Handle agent command (editors and admins only)
                if not await verify_session_access(session_id, user, "editor"):
                    await websocket.send_json({
                        "type": "error",
                        "message": "Insufficient permissions"
                    })
                    continue
                
                await websocket.send_json({
                    "type": "command_result",
                    "command": data.get("command"),
                    "result": f"Executed command: {data.get('command')}",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                
                DatabaseService.record_activity(
                    session_id=session_id,
                    user_id=user["id"],
                    activity_type="command_executed",
                    description=f"Command executed: {data.get('command')}"
                )
                
            elif data.get("type") == "ping":
                # Handle ping
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                
            elif data.get("type") == "get_users":
                # Send list of connected users
                connected_users = websocket_manager.get_connected_users(session_id)
                await websocket.send_json({
                    "type": "users_list",
                    "users": connected_users
                })
                
    except WebSocketDisconnect:
        await websocket_manager.disconnect(websocket, session_id)
    except Exception as e:
        print(f"WebSocket error: {e}")
        await websocket_manager.disconnect(websocket, session_id)

# ============== VNC ENDPOINTS ==============
@app.get("/api/sessions/{session_id}/vnc")
async def get_vnc_info(
    session_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Get VNC connection info"""
    # Check if user has access to session
    if not await verify_session_access(session_id, current_user, "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this session"
        )
    
    session = DatabaseService.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    if not session.get('vnc_port'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VNC not configured for this session"
        )
    
    return {
        "session_id": session_id,
        "vnc_port": session['vnc_port'],
        "vnc_password": session.get('vnc_password'),
        "websocket_url": f"ws://localhost:8000/api/sessions/{session_id}/vnc/ws",
        "novnc_url": f"http://localhost:6080/vnc.html?host=localhost&port={session['vnc_port']}"
    }

@app.websocket("/api/sessions/{session_id}/vnc/ws")
async def vnc_websocket(
    websocket: WebSocket, 
    session_id: str,
    token: str = Query(...)
):
    """VNC WebSocket proxy with authentication"""
    # Authenticate user
    try:
        user = DatabaseService.get_user(token)
        if not user:
            await websocket.close(code=1008, reason="Invalid token")
            return
    except:
        await websocket.close(code=1008, reason="Authentication required")
        return
    
    # Check session access
    if not await verify_session_access(session_id, user, "viewer"):
        await websocket.close(code=1008, reason="Access denied")
        return
    
    session = DatabaseService.get_session(session_id)
    if not session:
        await websocket.close(code=1008, reason="Session not found")
        return
    
    if not session.get('vnc_port'):
        await websocket.close(code=1008, reason="VNC not available")
        return
    
    await vnc_proxy.proxy_websocket(
        websocket,
        vnc_port=session['vnc_port'],
        password=session.get('vnc_password', '')
    )

# ============== ACTIVITY ENDPOINTS ==============
@app.get("/api/sessions/{session_id}/activities")
async def get_session_activities(
    session_id: str,
    limit: int = Query(20, ge=1, le=100),
    current_user: Dict = Depends(get_current_user)
):
    """Get session activities"""
    # Check if user has access to session
    if not await verify_session_access(session_id, current_user, "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this session"
        )
    
    activities = DatabaseService.get_session_activities(session_id, limit)
    return activities

# ============== HEALTH & INFO ==============
@app.get("/")
async def root():
    return {
        "message": "Computer Use Agent Backend API",
        "version": "2.0.0",
        "ai_agent": "Ollama AI" if ollama_ai.available else "Simple AI (Fallback)",
        "authentication": "Enabled",
        "multi_user": "Enabled",
        "endpoints": {
            "auth": {
                "register": "/api/auth/register",
                "login": "/api/auth/login",
                "me": "/api/auth/me"
            },
            "sessions": {
                "create": "/api/sessions",
                "join": "/api/sessions/join",
                "list": "/api/sessions",
                "public": "/api/sessions/public",
                "get": "/api/sessions/{id}",
                "update": "/api/sessions/{id}",
                "delete": "/api/sessions/{id}",
                "users": "/api/sessions/{id}/users",
                "connected": "/api/sessions/{id}/connected"
            },
            "chat": {
                "send": "/api/chat/messages",
                "history": "/api/sessions/{id}/chat"
            },
            "streaming": "/api/sessions/{id}/stream",
            "websocket": "/api/sessions/{id}/ws",
            "vnc": "/api/sessions/{id}/vnc",
            "activities": "/api/sessions/{id}/activities"
        }
    }

@app.get("/health")
async def health_check():
    sessions = DatabaseService.list_sessions(None, False, 10)
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "connected",
        "ai_agent": "Ollama - Ready" if ollama_ai.available else "Simple AI - Ready",
        "total_sessions": len(sessions),
        "active_connections": sum(
            websocket_manager.get_connection_count(session['id']) 
            for session in sessions
        )
    }

@app.get("/stats")
async def get_stats(current_user: Dict = Depends(get_current_user)):
    """Get system statistics"""
    sessions = DatabaseService.list_sessions(current_user["id"], False, 1000)
    
    status_counts = {}
    for session in sessions:
        status = session.get('status', 'unknown')
        status_counts[status] = status_counts.get(status, 0) + 1
    
    total_sessions_all = len(DatabaseService.list_sessions(None, False, 1000))
    
    return {
        "user_sessions": len(sessions),
        "total_sessions_all": total_sessions_all,
        "status_counts": status_counts,
        "active_connections": sum(
            websocket_manager.get_connection_count(session['id']) 
            for session in sessions
        ),
        "user_info": {
            "user_id": current_user["id"],
            "username": current_user["username"]
        }
    }

# ============== RUN SCRIPT ==============
if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("COMPUTER USE AGENT BACKEND WITH AUTHENTICATION")
    print("=" * 60)
    
    if ollama_ai.available:
        print("✅ Ollama AI integrated")
        print("💡 To use Ollama models:")
        print("   1. Install Ollama: https://ollama.ai/")
        print("   2. Download a model: ollama pull llama3")
        print("   3. Run the server: ollama serve")
    else:
        print("⚠️  Ollama not installed")
        print("💡 To use real AI:")
        print("   pip install ollama")
    
    print("\n🔐 Authentication System:")
    print("   • Default admin: admin / admin123")
    print("   • AI Assistant user: ai_assistant (auto-created)")
    print("   • Register new users at /api/auth/register")
    print("   • Login at /api/auth/login")
    
    print("\n🔗 Starting server on http://localhost:8000")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("\n✨ Key Features:")
    print("   • Session passwords for access control")
    print("   • Multi-user sessions")
    print("   • Public/private sessions")
    print("   • WebSocket with authentication")
    print("   • Role-based access (viewer/editor/admin)")
    print("   • AI Assistant with proper user account")
    
    print("\n📋 Protected Endpoints (require Bearer token):")
    print("   • POST /api/sessions          - Create session")
    print("   • POST /api/sessions/join     - Join session with password")
    print("   • GET  /api/sessions/{id}/ws  - WebSocket (with token)")
    print("   • POST /api/chat/messages     - Send chat message")
    
    print("\n📋 Public Endpoints:")
    print("   • POST /api/auth/register     - Register user")
    print("   • POST /api/auth/login        - Login")
    print("   • GET  /api/sessions/public   - List public sessions")
    print("=" * 60)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=False
    )
