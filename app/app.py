from flask import Flask, render_template, request, jsonify
import os
import socket
import datetime
import json

app = Flask(__name__)

# Application version - this will change for demo
APP_VERSION = os.getenv('APP_VERSION', 'v1.0.0')
DEPLOYMENT_TIME = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

@app.route('/')
def home():
    return render_template('index.html', 
                         version=APP_VERSION,
                         deployment_time=DEPLOYMENT_TIME,
                         hostname=socket.gethostname())

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'version': APP_VERSION,
        'timestamp': datetime.datetime.now().isoformat(),
        'hostname': socket.gethostname()
    })

@app.route('/info')
def info():
    return jsonify({
        'app_name': 'St Joseph\'s DevOps Demo',
        'version': APP_VERSION,
        'deployment_time': DEPLOYMENT_TIME,
        'hostname': socket.gethostname(),
        'client_ip': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
        'user_agent': request.headers.get('User-Agent')
    })

# Intentional vulnerable endpoint for security demo
@app.route('/admin')
def admin():
    # This will be caught by security scanning
    user_input = request.args.get('cmd', '')
    if user_input:
        # NEVER do this in production - demo of security issue
        return f"Command: {user_input}"
    return "Admin panel"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)