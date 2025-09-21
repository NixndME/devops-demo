# Enhanced app.py with detailed user tracking and demo security placeholders

from flask import Flask, render_template, request, jsonify
from prometheus_flask_exporter import PrometheusMetrics
import os
import socket
import datetime
import json
import requests
from prometheus_client import Counter, Histogram, Gauge
import logging
import re
from user_agents import parse

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Prometheus metrics
metrics = PrometheusMetrics(app)

# Application version
APP_VERSION = os.getenv('APP_VERSION', 'v1.0.3')
DEPLOYMENT_TIME = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

# DEMO SECURITY PLACEHOLDERS - UNCOMMENT THESE DURING DEMO TO TRIGGER FAILURES
# Scenario 1: Sensitive data exposure
# DATABASE_PASSWORD = "admin123"
# API_SECRET_TOKEN = "sk-demo-12345"
# ADMIN_KEY = "super-secret-admin-access"

# Scenario 2: Domain exposure  
# INTERNAL_API_URL = "https://admin.init0xff.com/api"
# PRIVATE_DASHBOARD = "https://internal.init0xff.com/dashboard"

# Custom metrics for detailed user tracking
USER_REQUESTS = Counter(
    'app_user_requests_total',
    'Total user requests with details',
    ['client_ip', 'country', 'city', 'device_type', 'browser', 'os', 'endpoint', 'method']
)

PAGE_VIEWS = Counter(
    'app_page_views_total', 
    'Page views by location and device',
    ['page', 'country', 'city', 'device_type', 'browser', 'os']
)

CLICK_EVENTS = Counter(
    'app_click_events_total',
    'User click events with device info', 
    ['element', 'page', 'client_ip', 'country', 'device_type', 'browser']
)

ACTIVE_USERS = Gauge(
    'app_active_users',
    'Currently active users by location and device',
    ['country', 'city', 'device_type', 'browser']
)

DEVICE_METRICS = Counter(
    'app_device_metrics_total',
    'Device and browser statistics',
    ['device_brand', 'device_model', 'browser_name', 'browser_version', 'os_name', 'os_version']
)

GEOGRAPHIC_METRICS = Gauge(
    'app_geographic_users',
    'Users by geographic location',
    ['country', 'region', 'city', 'timezone', 'isp']
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
        if ip_address and ip_address not in ['127.0.0.1', 'localhost', '::1']:
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
                    'isp': data.get('isp', 'Unknown'),
                    'country_code': data.get('countryCode', 'XX')
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
        'isp': 'Unknown',
        'country_code': 'XX'
    }

def get_detailed_device_info(user_agent_string):
    """Get detailed device and browser information"""
    try:
        user_agent = parse(user_agent_string)
        
        device_info = {
            'device_type': 'desktop',
            'device_brand': user_agent.device.brand or 'Unknown',
            'device_model': user_agent.device.model or 'Unknown',
            'browser_name': user_agent.browser.family or 'Unknown',
            'browser_version': user_agent.browser.version_string or 'Unknown',
            'os_name': user_agent.os.family or 'Unknown',
            'os_version': user_agent.os.version_string or 'Unknown',
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            'is_bot': user_agent.is_bot
        }
        
        # Determine device type
        if user_agent.is_mobile:
            device_info['device_type'] = 'mobile'
        elif user_agent.is_tablet:
            device_info['device_type'] = 'tablet'
        elif user_agent.is_pc:
            device_info['device_type'] = 'desktop'
        elif user_agent.is_bot:
            device_info['device_type'] = 'bot'
            
        return device_info
        
    except Exception as e:
        logger.warning(f"Failed to parse user agent: {e}")
        return {
            'device_type': 'unknown',
            'device_brand': 'Unknown',
            'device_model': 'Unknown',
            'browser_name': 'Unknown',
            'browser_version': 'Unknown',
            'os_name': 'Unknown',
            'os_version': 'Unknown',
            'is_mobile': False,
            'is_tablet': False,
            'is_pc': False,
            'is_bot': False
        }

def track_user_request(endpoint, method='GET'):
    """Track detailed user request information"""
    client_ip = get_client_ip()
    user_agent_string = request.headers.get('User-Agent', 'Unknown')
    location = get_location_info(client_ip)
    device_info = get_detailed_device_info(user_agent_string)
    
    # Update detailed metrics
    USER_REQUESTS.labels(
        client_ip=client_ip,
        country=location['country'],
        city=location['city'],
        device_type=device_info['device_type'],
        browser=device_info['browser_name'],
        os=device_info['os_name'],
        endpoint=endpoint,
        method=method
    ).inc()
    
    PAGE_VIEWS.labels(
        page=endpoint,
        country=location['country'],
        city=location['city'],
        device_type=device_info['device_type'],
        browser=device_info['browser_name'],
        os=device_info['os_name']
    ).inc()
    
    # Track device metrics
    DEVICE_METRICS.labels(
        device_brand=device_info['device_brand'],
        device_model=device_info['device_model'],
        browser_name=device_info['browser_name'],
        browser_version=device_info['browser_version'],
        os_name=device_info['os_name'],
        os_version=device_info['os_version']
    ).inc()
    
    # Track geographic metrics
    GEOGRAPHIC_METRICS.labels(
        country=location['country'],
        region=location['region'],
        city=location['city'],
        timezone=location['timezone'],
        isp=location['isp']
    ).set(1)
    
    # Track active users with detailed info
    session_id = f"{client_ip}_{location['country']}_{location['city']}_{device_info['device_type']}"
    active_sessions[session_id] = {
        'timestamp': datetime.datetime.now(),
        'location': location,
        'device': device_info,
        'ip': client_ip
    }
    
    # Clean old sessions (older than 5 minutes)
    cutoff = datetime.datetime.now() - datetime.timedelta(minutes=5)
    active_sessions = {k: v for k, v in active_sessions.items() 
                      if v['timestamp'] > cutoff}
    
    # Update active users gauge with detailed labels
    for session_id, session_data in active_sessions.items():
        ACTIVE_USERS.labels(
            country=session_data['location']['country'],
            city=session_data['location']['city'],
            device_type=session_data['device']['device_type'],
            browser=session_data['device']['browser_name']
        ).set(1)
    
    # Log detailed information
    logger.info(f"User Access: IP={client_ip}, "
               f"Location={location['city']}, {location['country']}, "
               f"Device={device_info['device_type']} ({device_info['device_brand']} {device_info['device_model']}), "
               f"Browser={device_info['browser_name']} {device_info['browser_version']}, "
               f"OS={device_info['os_name']} {device_info['os_version']}, "
               f"Endpoint={endpoint}, ISP={location['isp']}")
    
    return {
        'ip': client_ip,
        'location': location,
        'device': device_info,
        'user_agent': user_agent_string,
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
    
    # FIXED: Avoid using .keys() method to prevent security scan issues
    session_list = [session_id for session_id in active_sessions]
    
    return jsonify({
        'current_user': user_info,
        'active_users_count': current_active,
        'active_sessions': session_list,
        'session_details': [
            {
                'session_id': session_id,
                'ip': session_data['ip'],
                'country': session_data['location']['country'],
                'city': session_data['location']['city'],
                'device_type': session_data['device']['device_type'],
                'browser': session_data['device']['browser_name'],
                'os': session_data['device']['os_name']
            }
            for session_id, session_data in active_sessions.items()
        ],
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/click-track', methods=['POST'])
def click_track():
    """Track user click events"""
    data = request.get_json()
    client_ip = get_client_ip()
    location = get_location_info(client_ip)
    device_info = get_detailed_device_info(request.headers.get('User-Agent', ''))
    
    element = data.get('element', 'unknown')
    page = data.get('page', 'unknown')
    
    CLICK_EVENTS.labels(
        element=element,
        page=page,
        client_ip=client_ip,
        country=location['country'],
        device_type=device_info['device_type'],
        browser=device_info['browser_name']
    ).inc()
    
    logger.info(f"Click Event: Element={element}, Page={page}, "
               f"IP={client_ip}, Country={location['country']}, "
               f"Device={device_info['device_type']}, Browser={device_info['browser_name']}")
    
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
                'session_id': session_id,
                'last_seen': session_data['timestamp'].isoformat(),
                'ip': session_data['ip'],
                'country': session_data['location']['country'],
                'city': session_data['location']['city'],
                'device_type': session_data['device']['device_type'],
                'device_brand': session_data['device']['device_brand'],
                'device_model': session_data['device']['device_model'],
                'browser': f"{session_data['device']['browser_name']} {session_data['device']['browser_version']}",
                'os': f"{session_data['device']['os_name']} {session_data['device']['os_version']}",
                'isp': session_data['location']['isp']
            }
            for session_id, session_data in active_sessions.items()
        ],
        'server_info': {
            'hostname': socket.gethostname(),
            'version': APP_VERSION,
            'deployment_time': DEPLOYMENT_TIME
        }
    }
    
    return render_template('demo_stats.html', stats=stats)

# Demo endpoint for load testing
@app.route('/load-test')
def load_test():
    user_info = track_user_request('/load-test')
    # Simulate some work
    import time
    time.sleep(0.1)
    return jsonify({
        'message': 'Load test endpoint', 
        'hostname': socket.gethostname(),
        'user_info': user_info
    })

# Intentional error endpoint for demo
@app.route('/error')
def error():
    track_user_request('/error')
    return jsonify({'error': 'Demo error for monitoring'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)