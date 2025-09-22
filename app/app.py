
from flask import Flask, render_template, request, jsonify
from prometheus_flask_exporter import PrometheusMetrics
import os
import socket
import datetime
import json
import requests
from prometheus_client import Counter, Histogram, Gauge
import logging
import threading
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import hashlib
import time
from user_agents import parse
from collections import defaultdict
import traceback

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Prometheus metrics
metrics = PrometheusMetrics(app)

# Application configuration
APP_VERSION = os.getenv('APP_VERSION', 'v1.0.12')
DEPLOYMENT_TIME = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
DEMO_MODE = os.getenv('DEMO_MODE', 'devops-kubernetes')
ENHANCED_TRACKING = os.getenv('ENHANCED_TRACKING', 'true').lower() == 'true'
GEOLOCATION_ENABLED = os.getenv('GEOLOCATION_ENABLED', 'true').lower() == 'true'
GEOLOCATION_TIMEOUT = float(os.getenv('GEOLOCATION_TIMEOUT', '2.0'))
MAX_WORKERS = int(os.getenv('MAX_WORKERS', '8'))
RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
####
DATABASE_PASSWORD = "admin123"
API_SECRET_TOKEN = "sk-demo-12345"

# Thread pool for async operations
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# Demo-specific metrics for thousands of users
DEMO_USER_VISITS = Counter(
    'demo_user_visits_total',
    'Total user visits tracked',
    ['country', 'city', 'device_type', 'browser', 'os', 'isp']
)

DEMO_ACTIVE_SESSIONS = Gauge(
    'demo_active_sessions',
    'Currently active demo sessions',
    ['country', 'device_type', 'browser']
)

DEMO_GEOLOCATION_STATS = Counter(
    'demo_geolocation_stats_total',
    'Geolocation lookup statistics',
    ['status', 'service', 'ip_type']
)

DEMO_DEVICE_FINGERPRINTS = Gauge(
    'demo_unique_device_fingerprints',
    'Unique device fingerprints seen'
)

DEMO_PAGE_VIEWS = Counter(
    'demo_page_views_total',
    'Page views by endpoint',
    ['endpoint', 'method', 'status']
)

DEMO_ERRORS = Counter(
    'demo_errors_total',
    'Application errors by type',
    ['error_type', 'endpoint']
)

# Thread-safe storage for thousands of users
active_sessions = {}
device_fingerprints = {}
geolocation_cache = {}
rate_limit_tracker = defaultdict(list)

# Locks for thread safety
sessions_lock = threading.RLock()
cache_lock = threading.RLock()
rate_limit_lock = threading.RLock()

# Configuration constants
CACHE_DURATION = 3600  # 1 hour cache for demo stability
SESSION_TIMEOUT = 300  # 5 minutes session timeout
RATE_LIMIT_WINDOW = 60  # 1 minute rate limit window
MAX_REQUESTS_PER_IP = 30  # Max requests per IP per minute

def get_client_ip():
    """Get real client IP with comprehensive header checking"""
    try:
        # Check various headers that might contain real IP
        headers_to_check = [
            'X-Forwarded-For',
            'X-Real-IP', 
            'X-Original-Forwarded-For',
            'CF-Connecting-IP',
            'True-Client-IP',
            'X-Client-IP',
            'X-Cluster-Client-IP'
        ]
        
        for header in headers_to_check:
            if request.headers.get(header):
                # Take first IP if comma-separated, clean it
                ip = request.headers.get(header).split(',')[0].strip()
                if ip and ip not in ['unknown', 'localhost', '127.0.0.1', '::1']:
                    return ip
        
        # Fallback to remote_addr
        remote_addr = request.remote_addr
        return remote_addr if remote_addr else 'unknown'
        
    except Exception as e:
        logger.debug(f"Error getting client IP: {e}")
        return 'unknown'

def check_rate_limit(ip_address):
    """Simple rate limiting to prevent abuse"""
    if not RATE_LIMIT_ENABLED:
        return True
        
    try:
        with rate_limit_lock:
            now = time.time()
            # Clean old entries
            rate_limit_tracker[ip_address] = [
                timestamp for timestamp in rate_limit_tracker[ip_address]
                if now - timestamp < RATE_LIMIT_WINDOW
            ]
            
            # Check rate limit
            if len(rate_limit_tracker[ip_address]) >= MAX_REQUESTS_PER_IP:
                return False
                
            # Add current request
            rate_limit_tracker[ip_address].append(now)
            return True
            
    except Exception as e:
        logger.debug(f"Rate limit check error: {e}")
        return True  # Allow on error

def generate_device_fingerprint(user_agent, headers, ip):
    """Generate device fingerprint for tracking"""
    try:
        fingerprint_data = {
            'user_agent': user_agent[:200],  # Truncate to prevent huge fingerprints
            'accept_language': headers.get('Accept-Language', '')[:50],
            'accept_encoding': headers.get('Accept-Encoding', '')[:50],
            'accept': headers.get('Accept', '')[:100],
            'ip_class': '.'.join(ip.split('.')[:2]) if '.' in ip else 'unknown'  # Class B network
        }
        
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
        return fingerprint_hash
        
    except Exception as e:
        logger.debug(f"Fingerprint generation error: {e}")
        return hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]

def robust_geolocation_lookup(ip_address):
    """Ultra-robust geolocation with multiple fallbacks"""
    ip_type = 'internal' if any(ip_address.startswith(prefix) for prefix in ['10.', '192.168.', '172.', '127.']) else 'external'
    
    # Check cache first
    with cache_lock:
        if ip_address in geolocation_cache:
            cache_entry = geolocation_cache[ip_address]
            if time.time() - cache_entry['timestamp'] < CACHE_DURATION:
                return cache_entry['data']
    
    # Default fallback data
    fallback_data = {
        'country': 'Unknown',
        'city': 'Unknown',
        'region': 'Unknown',
        'latitude': 0,
        'longitude': 0,
        'timezone': 'Unknown',
        'isp': 'Unknown',
        'org': 'Unknown',
        'asn': 'Unknown',
        'ip_type': ip_type,
        'lookup_service': 'fallback',
        'lookup_success': False
    }
    
    # Don't try external lookups for internal IPs
    if ip_type == 'internal' or ip_address in ['unknown', '127.0.0.1', 'localhost', '::1']:
        fallback_data.update({
            'country': 'Internal Network',
            'city': 'Local',
            'isp': 'Internal'
        })
        with cache_lock:
            geolocation_cache[ip_address] = {
                'data': fallback_data,
                'timestamp': time.time()
            }
        return fallback_data
    
    # Try external geolocation services with robust error handling
    services = [
        {
            'url': f'http://ip-api.com/json/{ip_address}?fields=country,regionName,city,lat,lon,timezone,isp,org,as,query,status',
            'timeout': GEOLOCATION_TIMEOUT,
            'parser': 'ip_api'
        },
        {
            'url': f'https://ipapi.co/{ip_address}/json/',
            'timeout': GEOLOCATION_TIMEOUT,
            'parser': 'ipapi_co'
        }
    ]
    
    for service in services:
        try:
            response = requests.get(
                service['url'],
                timeout=service['timeout'],
                headers={
                    'User-Agent': f'StJosephs-DevOps-Demo/{APP_VERSION}',
                    'Accept': 'application/json'
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if service['parser'] == 'ip_api' and data.get('status') == 'success':
                    location_data = {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'timezone': data.get('timezone', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'asn': data.get('as', 'Unknown'),
                        'ip_type': ip_type,
                        'lookup_service': 'ip-api.com',
                        'lookup_success': True
                    }
                    
                    # Cache successful result
                    with cache_lock:
                        geolocation_cache[ip_address] = {
                            'data': location_data,
                            'timestamp': time.time()
                        }
                    
                    DEMO_GEOLOCATION_STATS.labels(
                        status='success', 
                        service='ip-api.com', 
                        ip_type=ip_type
                    ).inc()
                    
                    return location_data
                    
                elif service['parser'] == 'ipapi_co' and 'error' not in data:
                    location_data = {
                        'country': data.get('country_name', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('region', 'Unknown'),
                        'latitude': data.get('latitude', 0),
                        'longitude': data.get('longitude', 0),
                        'timezone': data.get('timezone', 'Unknown'),
                        'isp': data.get('org', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'asn': data.get('asn', 'Unknown'),
                        'ip_type': ip_type,
                        'lookup_service': 'ipapi.co',
                        'lookup_success': True
                    }
                    
                    # Cache successful result
                    with cache_lock:
                        geolocation_cache[ip_address] = {
                            'data': location_data,
                            'timestamp': time.time()
                        }
                    
                    DEMO_GEOLOCATION_STATS.labels(
                        status='success', 
                        service='ipapi.co', 
                        ip_type=ip_type
                    ).inc()
                    
                    return location_data
                    
        except Exception as e:
            logger.debug(f"Geolocation service {service['url']} failed: {e}")
            DEMO_GEOLOCATION_STATS.labels(
                status='failed', 
                service=service.get('parser', 'unknown'), 
                ip_type=ip_type
            ).inc()
            continue
    
    # All services failed - return fallback and cache it
    DEMO_GEOLOCATION_STATS.labels(
        status='fallback', 
        service='none', 
        ip_type=ip_type
    ).inc()
    
    with cache_lock:
        geolocation_cache[ip_address] = {
            'data': fallback_data,
            'timestamp': time.time()
        }
    
    return fallback_data

def get_location_info(ip_address):
    """Get location with timeout and fallback handling"""
    if not GEOLOCATION_ENABLED:
        return {
            'country': 'Geolocation Disabled',
            'city': 'Demo Mode',
            'region': 'Unknown',
            'latitude': 0,
            'longitude': 0,
            'timezone': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown',
            'asn': 'Unknown',
            'ip_type': 'disabled',
            'lookup_service': 'disabled',
            'lookup_success': False
        }
    
    try:
        # Use thread pool with timeout
        future = executor.submit(robust_geolocation_lookup, ip_address)
        return future.result(timeout=GEOLOCATION_TIMEOUT + 1.0)
        
    except TimeoutError:
        logger.debug(f"Geolocation timeout for {ip_address}")
        DEMO_GEOLOCATION_STATS.labels(
            status='timeout', 
            service='any', 
            ip_type='timeout'
        ).inc()
        
        # Return immediate fallback on timeout
        return robust_geolocation_lookup(ip_address)
        
    except Exception as e:
        logger.debug(f"Geolocation error for {ip_address}: {e}")
        DEMO_GEOLOCATION_STATS.labels(
            status='error', 
            service='any', 
            ip_type='error'
        ).inc()
        
        # Return immediate fallback on any error
        return robust_geolocation_lookup(ip_address)

def get_device_info(user_agent_string):
    """Get device information with error handling"""
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
        logger.debug(f"Device info parsing error: {e}")
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

def cleanup_old_sessions():
    """Clean up old sessions to prevent memory leaks"""
    try:
        with sessions_lock:
            current_time = time.time()
            expired_sessions = [
                session_id for session_id, session_data in active_sessions.items()
                if current_time - session_data['timestamp'] > SESSION_TIMEOUT
            ]
            
            for session_id in expired_sessions:
                del active_sessions[session_id]
                
            if expired_sessions:
                logger.debug(f"Cleaned up {len(expired_sessions)} expired sessions")
                
    except Exception as e:
        logger.error(f"Session cleanup error: {e}")

def track_user_request(endpoint, method='GET'):
    """Comprehensive user tracking with robust error handling"""
    try:
        # Get basic request info
        client_ip = get_client_ip()
        user_agent_string = request.headers.get('User-Agent', 'Unknown')
        
        # Check rate limiting
        if not check_rate_limit(client_ip):
            DEMO_ERRORS.labels(error_type='rate_limited', endpoint=endpoint).inc()
            logger.warning(f"Rate limited IP: {client_ip}")
            return {
                'error': 'rate_limited',
                'ip': client_ip,
                'timestamp': datetime.datetime.now().isoformat()
            }
        
        # Get device info (always works)
        device_info = get_device_info(user_agent_string)
        
        # Generate fingerprint
        headers = dict(request.headers)
        fingerprint = generate_device_fingerprint(user_agent_string, headers, client_ip)
        
        # Get location info (with robust fallbacks)
        location = get_location_info(client_ip)
        
        # Update metrics
        DEMO_USER_VISITS.labels(
            country=location['country'],
            city=location['city'],
            device_type=device_info['device_type'],
            browser=device_info['browser_name'],
            os=device_info['os_name'],
            isp=location['isp']
        ).inc()
        
        DEMO_PAGE_VIEWS.labels(
            endpoint=endpoint,
            method=method,
            status='success'
        ).inc()
        
        # Track session
        session_data = {
            'timestamp': time.time(),
            'ip': client_ip,
            'location': location,
            'device': device_info,
            'fingerprint': fingerprint,
            'user_agent': user_agent_string[:200],  # Truncate long user agents
            'visit_count': 1
        }
        
        with sessions_lock:
            if fingerprint in active_sessions:
                session_data['visit_count'] = active_sessions[fingerprint]['visit_count'] + 1
            
            active_sessions[fingerprint] = session_data
            
            # Update active sessions gauge
            DEMO_ACTIVE_SESSIONS.labels(
                country=location['country'],
                device_type=device_info['device_type'],
                browser=device_info['browser_name']
            ).set(len(active_sessions))
            
            # Update unique fingerprints
            DEMO_DEVICE_FINGERPRINTS.set(len(active_sessions))
        
        # Periodic cleanup
        if len(active_sessions) % 100 == 0:  # Every 100 requests
            cleanup_old_sessions()
        
        # Log for demo (only non-health endpoints)
        if endpoint not in ['/health', '/readiness', '/metrics']:
            logger.info(f"DEMO - Visitor: IP={client_ip}, "
                       f"Location={location['city']}, {location['country']}, "
                       f"Device={device_info['device_type']}, "
                       f"Browser={device_info['browser_name']}, "
                       f"OS={device_info['os_name']}, "
                       f"ISP={location['isp']}")
        
        return {
            'ip': client_ip,
            'location': location,
            'device': device_info,
            'fingerprint': fingerprint,
            'user_agent': user_agent_string,
            'visit_count': session_data['visit_count'],
            'timestamp': datetime.datetime.now().isoformat(),
            'demo_note': 'St Joseph\'s DevOps & Kubernetes Demo'
        }
        
    except Exception as e:
        logger.error(f"Tracking error for {endpoint}: {e}")
        DEMO_ERRORS.labels(error_type='tracking_error', endpoint=endpoint).inc()
        
        # Return minimal safe data on any error
        return {
            'ip': 'error',
            'location': {'country': 'Error', 'city': 'Error', 'isp': 'Error'},
            'device': {'device_type': 'error', 'browser_name': 'error', 'os_name': 'error'},
            'fingerprint': 'error',
            'user_agent': 'error',
            'visit_count': 1,
            'timestamp': datetime.datetime.now().isoformat(),
            'demo_note': 'Error in tracking - demo continues'
        }

# Routes
@app.route('/')
def home():
    user_info = track_user_request('/')
    return render_template('index.html', 
                         version=APP_VERSION,
                         deployment_time=DEPLOYMENT_TIME,
                         hostname=socket.gethostname(),
                         user_info=user_info,
                         demo_title="St Joseph's College - DevOps & Kubernetes Demo")

@app.route('/health')
def health():
    """Ultra-lightweight health check for K8s"""
    try:
        return jsonify({
            'status': 'healthy',
            'version': APP_VERSION,
            'timestamp': datetime.datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'demo': 'devops-kubernetes'
        }), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/readiness')
def readiness():
    """Readiness probe for K8s"""
    try:
        with sessions_lock:
            session_count = len(active_sessions)
        
        return jsonify({
            'status': 'ready',
            'version': APP_VERSION,
            'active_sessions': session_count,
            'cache_size': len(geolocation_cache),
            'timestamp': datetime.datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({'status': 'not_ready', 'error': str(e)}), 503

@app.route('/info')
def info():
    user_info = track_user_request('/info')
    return jsonify({
        'demo_name': 'St Joseph\'s College - DevOps & Kubernetes Demo',
        'version': APP_VERSION,
        'deployment_time': DEPLOYMENT_TIME,
        'hostname': socket.gethostname(),
        'user_details': user_info,
        'features': {
            'geolocation_enabled': GEOLOCATION_ENABLED,
            'enhanced_tracking': ENHANCED_TRACKING,
            'rate_limiting': RATE_LIMIT_ENABLED
        }
    })

@app.route('/analytics')
def analytics():
    """Real-time analytics for demo"""
    user_info = track_user_request('/analytics')
    
    with sessions_lock:
        current_sessions = dict(active_sessions)
    
    analytics_data = {
        'current_user': user_info,
        'total_active_sessions': len(current_sessions),
        'unique_countries': len(set(s['location']['country'] for s in current_sessions.values())),
        'unique_devices': len(set(s['device']['device_type'] for s in current_sessions.values())),
        'cache_stats': {
            'geolocation_cache_size': len(geolocation_cache),
            'session_cache_size': len(current_sessions)
        },
        'recent_visitors': [
            {
                'ip': s['ip'],
                'country': s['location']['country'],
                'city': s['location']['city'],
                'device': s['device']['device_type'],
                'browser': s['device']['browser_name'],
                'visits': s['visit_count']
            }
            for s in sorted(current_sessions.values(), key=lambda x: x['timestamp'], reverse=True)[:10]
        ]
    }
    
    return jsonify(analytics_data)

@app.route('/demo-stats')
def demo_stats():
    """Live demo statistics page"""
    user_info = track_user_request('/demo-stats')
    
    with sessions_lock:
        current_sessions = dict(active_sessions)
    
    stats = {
        'current_visitor': user_info,
        'total_sessions': len(current_sessions),
        'demo_info': {
            'title': 'St Joseph\'s College - DevOps & Kubernetes Demo',
            'version': APP_VERSION,
            'deployment_time': DEPLOYMENT_TIME,
            'hostname': socket.gethostname()
        },
        'session_details': [
            {
                'ip': session['ip'],
                'country': session['location']['country'],
                'city': session['location']['city'],
                'device_type': session['device']['device_type'],
                'browser': session['device']['browser_name'],
                'os': session['device']['os_name'],
                'isp': session['location']['isp'],
                'visits': session['visit_count'],
                'fingerprint': session['fingerprint']
            }
            for session in sorted(current_sessions.values(), key=lambda x: x['timestamp'], reverse=True)
        ]
    }
    
    return render_template('demo_stats.html', stats=stats)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    DEMO_ERRORS.labels(error_type='404', endpoint=request.endpoint or 'unknown').inc()
    return jsonify({'error': 'Not found', 'demo': 'St Joseph\'s DevOps Demo'}), 404

@app.errorhandler(500)
def internal_error(error):
    DEMO_ERRORS.labels(error_type='500', endpoint=request.endpoint or 'unknown').inc()
    return jsonify({'error': 'Internal server error', 'demo': 'St Joseph\'s DevOps Demo'}), 500

# Graceful shutdown
def signal_handler(sig, frame):
    logger.info(f'DevOps demo app received signal {sig}, shutting down gracefully...')
    try:
        executor.shutdown(wait=True, timeout=5)
    except:
        pass
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    logger.info(f"Starting St Joseph's DevOps & Kubernetes Demo - Version {APP_VERSION}")
    logger.info(f"Enhanced Tracking: {ENHANCED_TRACKING}")
    logger.info(f"Geolocation Enabled: {GEOLOCATION_ENABLED}")
    logger.info(f"Rate Limiting: {RATE_LIMIT_ENABLED}")
    logger.info(f"Max Workers: {MAX_WORKERS}")
    app.run(host='0.0.0.0', port=5000, debug=False)