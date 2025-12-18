# AI Chat Daemon
The AI Daemon is a lightweight, pure-Python autonomous assistant designed to act as a programming copilot. It runs as a background daemon and connects to an Ollama-powered local LLM server, enabling fast, private, and offline-capable AI assistance for software development.

Built entirely in Python, the AI Daemon integrates seamlessly into development workflows, providing real-time support for coding tasks such as:

- Code generation and refactoring
- Debugging and error analysis
- Explaining existing codebases
- Writing tests and documentation
- Assisting with architecture and design decisions

By leveraging Ollama on the server side, the AI Daemon avoids cloud dependencies, ensuring low latency, data privacy, and full control over the models used. Its daemon-based architecture allows it to remain always available, responding to requests from editors, CLIs, or other tools without interrupting the developer’s workflow.

The AI Daemon is designed to be:

- Efficient – minimal overhead, optimized for continuous use
- Developer-focused – acts as a true copilot, not just a chatbot

In short, the AI Daemon transforms a local LLM into a reliable, always-on Python-based coding copilot, tailored for developers who value performance, privacy, and control.

### 0. INSTALLATION
#### Dependencies
```
pip install requests prompt_toolkit websockets fastapi "pydantic>=2.0" bcrypt uvicorn
```
#### Ollama and Models
```
curl -fsSL https://ollama.com/install.sh | sh
ollama pull codellama:7b-instruct
ollama pull deepseek-r1:latest
ollama pull wizardcoder:33b               // 18GB
ollama pull deepseek-coder:33b-instruct   // 18GB
ollama pull deepseek-coder:1.3b           // 700MB
```
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
python client.py --session abc-123-def --message "What time is it?"
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
python client.py --url http://remote:8000 --create "My Session"
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
Usage: python chat.py SESSION_ID [--session SESSION_ID] [--url BASE_URL] [--username USERNAME] [--password PASSWORD] [--watch]

Examples:
  python chat.py SESSION_ID [--watch] (will prompt for credentials)
  python chat.py SESSION_ID --username USER --password PASS
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
