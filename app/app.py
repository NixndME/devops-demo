# from flask import Flask, render_template, request, jsonify
# import os
# import socket
# import datetime
# import json

# app = Flask(__name__)

# # Application version - this will change for demo
# APP_VERSION = os.getenv('APP_VERSION', 'v1.0.0')
# DEPLOYMENT_TIME = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

# @app.route('/')
# def home():
#     return render_template('index.html', 
#                          version=APP_VERSION,
#                          deployment_time=DEPLOYMENT_TIME,
#                          hostname=socket.gethostname())

# @app.route('/health')
# def health():
#     return jsonify({
#         'status': 'healthy',
#         'version': APP_VERSION,
#         'timestamp': datetime.datetime.now().isoformat(),
#         'hostname': socket.gethostname()
#     })

# @app.route('/info')
# def info():
#     return jsonify({
#         'app_name': 'St Joseph\'s DevOps Demo',
#         'version': APP_VERSION,
#         'deployment_time': DEPLOYMENT_TIME,
#         'hostname': socket.gethostname(),
#         'client_ip': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
#         'user_agent': request.headers.get('User-Agent')
#     })

# # Intentional vulnerable endpoint for security demo
# @app.route('/admin')
# def admin():
#     # This will be caught by security scanning
#     user_input = request.args.get('cmd', '')
#     if user_input:
#         # NEVER do this in production - demo of security issue
#         return f"Command: {user_input}"
#     return "Admin panel"

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)

# Enhanced app.py with detailed user tracking

from flask import Flask, render_template, request, jsonify
from prometheus_flask_exporter import PrometheusMetrics
import os
import socket
import datetime
import json
import requests
from prometheus_client import Counter, Histogram, Gauge
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Prometheus metrics
metrics = PrometheusMetrics(app)

# Application version
APP_VERSION = os.getenv('APP_VERSION', 'v1.0.3')
DEPLOYMENT_TIME = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

# Custom metrics for user tracking
USER_REQUESTS = Counter(
    'app_user_requests_total',
    'Total user requests with details',
    ['client_ip', 'country', 'city', 'user_agent_type', 'endpoint', 'method']
)

PAGE_VIEWS = Counter(
    'app_page_views_total', 
    'Page views by location',
    ['page', 'country', 'city', 'device_type']
)

CLICK_EVENTS = Counter(
    'app_click_events_total',
    'User click events', 
    ['element', 'page', 'client_ip', 'country']
)

ACTIVE_USERS = Gauge(
    'app_active_users',
    'Currently active users by location',
    ['country', 'city']
)

# Store for tracking active sessions
active_sessions = {}

def get_client_ip():
    """Get real client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def get_location_info(ip_address):
    """Get location information from IP address"""
    try:
        # Using a free IP geolocation service
        if ip_address and ip_address not in ['127.0.0.1', 'localhost']:
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=2)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'latitude': data.get('lat', 0),
                    'longitude': data.get('lon', 0),
                    'timezone': data.get('timezone', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }
    except Exception as e:
        logger.warning(f"Failed to get location for IP {ip_address}: {e}")
    
    return {
        'country': 'Unknown',
        'city': 'Unknown', 
        'region': 'Unknown',
        'latitude': 0,
        'longitude': 0,
        'timezone': 'Unknown',
        'isp': 'Unknown'
    }

def get_device_type(user_agent):
    """Determine device type from user agent"""
    user_agent = user_agent.lower()
    if 'mobile' in user_agent or 'android' in user_agent or 'iphone' in user_agent:
        return 'mobile'
    elif 'tablet' in user_agent or 'ipad' in user_agent:
        return 'tablet'
    else:
        return 'desktop'

def track_user_request(endpoint, method='GET'):
    """Track detailed user request information"""
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    location = get_location_info(client_ip)
    device_type = get_device_type(user_agent)
    
    # Update metrics
    USER_REQUESTS.labels(
        client_ip=client_ip,
        country=location['country'],
        city=location['city'],
        user_agent_type=device_type,
        endpoint=endpoint,
        method=method
    ).inc()
    
    PAGE_VIEWS.labels(
        page=endpoint,
        country=location['country'],
        city=location['city'],
        device_type=device_type
    ).inc()
    
    # Track active users
    session_id = f"{client_ip}_{location['country']}_{location['city']}"
    active_sessions[session_id] = datetime.datetime.now()
    
    # Clean old sessions (older than 5 minutes)
    cutoff = datetime.datetime.now() - datetime.timedelta(minutes=5)
    active_sessions = {k: v for k, v in active_sessions.items() if v > cutoff}
    
    # Update active users gauge
    for session in active_sessions:
        parts = session.split('_')
        if len(parts) >= 3:
            country = parts[1]
            city = parts[2]
            ACTIVE_USERS.labels(country=country, city=city).set(1)
    
    # Log detailed information
    logger.info(f"User Access: IP={client_ip}, Country={location['country']}, "
               f"City={location['city']}, Device={device_type}, "
               f"Endpoint={endpoint}, ISP={location['isp']}")
    
    return {
        'ip': client_ip,
        'location': location,
        'device_type': device_type,
        'user_agent': user_agent,
        'timestamp': datetime.datetime.now().isoformat()
    }

@app.route('/')
def home():
    user_info = track_user_request('/')
    return render_template('index.html', 
                         version=APP_VERSION,
                         deployment_time=DEPLOYMENT_TIME,
                         hostname=socket.gethostname(),
                         user_info=user_info)

@app.route('/health')
def health():
    track_user_request('/health')
    return jsonify({
        'status': 'healthy',
        'version': APP_VERSION,
        'timestamp': datetime.datetime.now().isoformat(),
        'hostname': socket.gethostname()
    })

@app.route('/info')
def info():
    user_info = track_user_request('/info')
    return jsonify({
        'app_name': 'St Joseph\'s DevOps Demo',
        'version': APP_VERSION,
        'deployment_time': DEPLOYMENT_TIME,
        'hostname': socket.gethostname(),
        'user_details': user_info
    })

@app.route('/analytics')
def analytics():
    """Real-time analytics endpoint"""
    user_info = track_user_request('/analytics')
    
    # Get current active users
    current_active = len(active_sessions)
    
    return jsonify({
        'current_user': user_info,
        'active_users_count': current_active,
        'active_sessions': list(active_sessions.keys()),
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/click-track', methods=['POST'])
def click_track():
    """Track user click events"""
    data = request.get_json()
    client_ip = get_client_ip()
    location = get_location_info(client_ip)
    
    element = data.get('element', 'unknown')
    page = data.get('page', 'unknown')
    
    CLICK_EVENTS.labels(
        element=element,
        page=page,
        client_ip=client_ip,
        country=location['country']
    ).inc()
    
    logger.info(f"Click Event: Element={element}, Page={page}, "
               f"IP={client_ip}, Country={location['country']}")
    
    return jsonify({'status': 'tracked'})

@app.route('/demo-stats')
def demo_stats():
    """Live demo statistics for presentation"""
    user_info = track_user_request('/demo-stats')
    
    # Get summary statistics
    stats = {
        'current_visitor': user_info,
        'total_active_sessions': len(active_sessions),
        'session_details': [
            {
                'session_id': session,
                'last_seen': timestamp.isoformat(),
                'country': session.split('_')[1] if len(session.split('_')) > 1 else 'Unknown',
                'city': session.split('_')[2] if len(session.split('_')) > 2 else 'Unknown'
            }
            for session, timestamp in active_sessions.items()
        ],
        'server_info': {
            'hostname': socket.gethostname(),
            'version': APP_VERSION,
            'deployment_time': DEPLOYMENT_TIME
        }
    }
    
    return render_template('demo_stats.html', stats=stats)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)