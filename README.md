# Computer Use Agent Client - AI Daemon

### 1. HEALTH & SYSTEM
```
python client.py --health                         # Check server status
python client.py --list                           # List all sessions
```
### 2. SESSION MANAGEMENT
```
python client.py --register
python client.py --login
python client.py --create "My Session"            # Create session
python client.py --session abc-123-def            # Get session info
python client.py --session abc-123-def --history  # View chat history
```
### 3. AGENT INTERACTION
```
python client.py --session abc-123-def --message "Open Chrome"
python client.py --session abc-123-def --message "Type 'Hello World'"
```
### 4. VNC & STREAMING
```
python client.py --session abc-123-def --vnc      # Get VNC connection info
python client.py --session abc-123-def --stream   # Real-time stream
python client.py --session abc-123-def --websocket # Interactive WebSocket
```
### 5. DEMO & REMOTE
```
python client.py --demo                           # Run complete demo
python client.py --url http://192.168.1.100:8000  # Connect to remote server
python client.py --url http://remote:8000 --create user1
```
### 6. INTERACTIVE MODE (MENU)
```
python client.py                                  # Start interactive menu
```
### 8. TROUBLESHOOTING
```
python client.py --help
python client.py --examples                            # Show usage examples
python client.py --url http://localhost:8080 --health  # Test connection
```

## Chat
```
Usage: python chat.py SESSION_ID [--session SESSION_ID] [--url BASE_URL] [--username USERNAME] [--password PASSWORD]

Examples:
  python chat.py session_123 --username admin --password admin123
  python chat.py session_123 (will prompt for credentials)
```

## Contribute
**Use issues for everything**
- You can help and get help by:
  - Reporting doubts and questions
- You can contribute by:
  - Reporting issues
  - Suggesting new features or enhancements
  - Improve/fix documentation

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2025 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
