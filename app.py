from flask import Flask, request, jsonify
import subprocess
import os
from functools import wraps

app = Flask(__name__)

# SECURITY: Set this in Render environment variables
AUTH_TOKEN = os.environ.get('AUTH_TOKEN', 'change-me')
ALLOWED_COMMANDS = ['ls', 'pwd', 'whoami', 'date', 'uptime', 'ps', 'df', 'free']

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if token != AUTH_TOKEN:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/execute', methods=['POST'])
@require_auth
def execute():
    data = request.get_json()
    command = data.get('command', '').strip()
    
    if not command:
        return jsonify({'error': 'No command provided'}), 400
    
    # Security: Only allow safe commands (customize as needed)
    cmd_parts = command.split()
    if cmd_parts[0] not in ALLOWED_COMMANDS:
        return jsonify({'error': f'Command "{cmd_parts[0]}" not allowed'}), 403
    
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=30
        )
        return jsonify({
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
