import os
import sys
import json
import time
import uuid
import logging
import hashlib
import socket
import requests
import redis as redis_lib

from flask import Flask, request, jsonify, Response, stream_with_context

# ─────────────────────────────────────────────
# Structured JSON logging
# ─────────────────────────────────────────────

class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            'ts':        self.formatTime(record, '%Y-%m-%dT%H:%M:%S'),
            'level':     record.levelname,
            'component': 'python',
            'msg':       record.getMessage(),
        }
        if record.exc_info:
            entry['error'] = self.formatException(record.exc_info)
        return json.dumps(entry)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JsonFormatter())
logging.root.handlers = [handler]
logging.root.setLevel(logging.INFO)
log = logging.getLogger('tspu_x')

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

SCALA_URL    = os.environ.get('SCALA_URL',    'http://127.0.0.1:8080')
SCALA_HEALTH = os.environ.get('SCALA_HEALTH', 'http://127.0.0.1:8081')
REDIS_URL    = os.environ.get('REDIS_URL',    'redis://127.0.0.1:6379/0')
RULES_FILE   = os.environ.get('RULES_FILE',   '/etc/tspu_x/rules.json')
ADMIN_PASS   = os.environ.get('ADMIN_PASS',   'admin')
ELIXIR_METRICS_URL = os.environ.get('ELIXIR_METRICS_URL', 'http://127.0.0.1:4043')
CPP_HEALTH_HOST    = os.environ.get('CPP_HEALTH_HOST', '127.0.0.1')
CPP_HEALTH_PORT    = int(os.environ.get('CPP_HEALTH_PORT', '4042'))

try:
    redis_client = redis_lib.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    log.info('Connected to Redis')
except Exception as e:
    log.error(f'Redis unavailable at startup: {e}')
    # crash-only: let Docker/systemd restart us
    sys.exit(1)

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'tspu-x-change-me-in-production')

# ─────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────

def _hash_pass(plaintext):
    return hashlib.sha256(plaintext.encode()).hexdigest()

def _check_token():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return None
    return redis_client.get(f'session:{token}')

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _check_token():
            return jsonify({'error': 'Unauthorised'}), 401
        return f(*args, **kwargs)
    return wrapper

@app.post('/api/auth/login')
def login():
    data = request.get_json(force=True) or {}
    password = data.get('password', '')
    stored_hash = redis_client.get('admin_pass_hash') or _hash_pass(ADMIN_PASS)
    if _hash_pass(password) != stored_hash:
        log.warning('Failed login attempt')
        return jsonify({'error': 'Wrong password'}), 403
    token = str(uuid.uuid4())
    redis_client.setex(f'session:{token}', 86400, '1')
    log.info('Admin authenticated')
    return jsonify({'token': token})

@app.post('/api/auth/logout')
@require_auth
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    redis_client.delete(f'session:{token}')
    return jsonify({'ok': True})

@app.post('/api/admin/password')
@require_auth
def change_password():
    data = request.get_json(force=True) or {}
    new_pass = data.get('password', '')
    if len(new_pass) < 6:
        return jsonify({'error': 'Password too short'}), 400
    redis_client.set('admin_pass_hash', _hash_pass(new_pass))
    return jsonify({'ok': True})

# ─────────────────────────────────────────────
# Rules CRUD — with Redis pub/sub for hot reload
# ─────────────────────────────────────────────

def _load_rules():
    stored = redis_client.get('rules_json')
    if stored:
        return json.loads(stored)
    try:
        with open(RULES_FILE) as f:
            return json.load(f)
    except Exception:
        return []

def _save_rules(rules):
    redis_client.set('rules_json', json.dumps(rules))
    try:
        os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
        with open(RULES_FILE, 'w') as f:
            json.dump(rules, f, indent=2)
    except Exception as e:
        log.warning(f'Could not write rules file: {e}')

def _publish(payload):
    redis_client.publish('tspu_rules', json.dumps(payload))

@app.get('/api/rules')
@require_auth
def get_rules():
    return jsonify(_load_rules())

@app.post('/api/rules')
@require_auth
def create_rule():
    rule = request.get_json(force=True) or {}
    if not rule.get('id'):
        rule['id'] = str(uuid.uuid4())
    rules = [r for r in _load_rules() if r['id'] != rule['id']]
    rules.append(rule)
    _save_rules(rules)
    _publish({'action': 'add', 'rule': rule})
    log.info(f'Rule created: {rule["id"]}')
    return jsonify(rule), 201

@app.delete('/api/rules/<rule_id>')
@require_auth
def delete_rule(rule_id):
    rules = [r for r in _load_rules() if r['id'] != rule_id]
    _save_rules(rules)
    _publish({'action': 'remove', 'id': rule_id})
    log.info(f'Rule deleted: {rule_id}')
    return jsonify({'ok': True})

@app.put('/api/rules/<rule_id>')
@require_auth
def update_rule(rule_id):
    updated = request.get_json(force=True) or {}
    updated['id'] = rule_id
    rules = [r for r in _load_rules() if r['id'] != rule_id]
    rules.append(updated)
    _save_rules(rules)
    _publish({'action': 'add', 'rule': updated})
    log.info(f'Rule updated: {rule_id}')
    return jsonify(updated)

# ─────────────────────────────────────────────
# Stats — proxy to Scala
# ─────────────────────────────────────────────

def _scala(path, params=None):
    try:
        r = requests.get(f'{SCALA_URL}/{path}', params=params, timeout=5)
        return r.json()
    except Exception as e:
        log.warning(f'Scala request failed: {e}')
        return {'error': str(e)}

@app.get('/api/stats/top')
@require_auth
def stats_top():
    now = int(time.time())
    return jsonify(_scala('api/top', {
        'ip':    request.args.get('ip'),
        'from':  request.args.get('from', now - 604800),
        'to':    request.args.get('to',   now),
        'limit': request.args.get('limit', 10),
    }))

@app.get('/api/stats/clients')
@require_auth
def stats_clients():
    now = int(time.time())
    return jsonify(_scala('api/clients', {
        'from': request.args.get('from', now - 86400),
        'to':   request.args.get('to',   now),
    }))

@app.get('/api/stats/domains')
@require_auth
def stats_domains():
    return jsonify(_scala('api/domains', {
        'ip':     request.args.get('ip'),
        'from':   request.args.get('from', 0),
        'to':     request.args.get('to', 9999999999),
        'search': request.args.get('search', ''),
        'sort':   request.args.get('sort', 'seconds'),
        'dir':    request.args.get('dir', 'desc'),
        'page':   request.args.get('page', 0),
        'size':   request.args.get('size', 20),
    }))

@app.get('/api/stats/day')
@require_auth
def stats_day():
    now = int(time.time())
    day_ts = request.args.get('day', now - (now % 86400))
    return jsonify(_scala('api/day', {'ip': request.args.get('ip'), 'day': day_ts}))

@app.get('/api/stats/export')
@require_auth
def stats_export():
    try:
        r = requests.get(
            f'{SCALA_URL}/api/export',
            params={
                'ip':   request.args.get('ip'),
                'from': request.args.get('from'),
                'to':   request.args.get('to', int(time.time())),
            },
            timeout=15
        )
        ip = request.args.get('ip', 'unknown')
        return Response(
            r.content,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=report_{ip}.csv'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─────────────────────────────────────────────
# Server-Sent Events — live activity stream
# ─────────────────────────────────────────────

@app.get('/api/events/live')
def live_events():
    # EventSource cannot set headers — accept token via query param as fallback
    token = (request.headers.get('Authorization', '').replace('Bearer ', '')
             or request.args.get('token', ''))
    if not token or not redis_client.get(f'session:{token}'):
        return jsonify({'error': 'Unauthorised'}), 401
    def generate():
        pubsub = redis_client.pubsub()
        pubsub.subscribe('tspu_live_events')
        try:
            for msg in pubsub.listen():
                if msg['type'] == 'message':
                    yield f'data: {msg["data"]}\n\n'
        finally:
            try:
                pubsub.close()
            except Exception:
                pass

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )

# ─────────────────────────────────────────────
# Health + Metrics
# ─────────────────────────────────────────────

def _check_component_health(url):
    try:
        r = requests.get(url + '/health', timeout=2)
        return r.status_code == 200
    except Exception:
        return False

def _check_cpp_health():
    try:
        with socket.create_connection((CPP_HEALTH_HOST, CPP_HEALTH_PORT), timeout=2) as s:
            s.recv(512)
        return True
    except Exception:
        return False

@app.delete('/api/stats/delete')
@require_auth
def delete_client_stats():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({'error': 'ip required'}), 400
    try:
        r = requests.delete(f'{SCALA_URL}/api/stats?ip={ip}', timeout=5)
        log.info(f'Deleted stats for {ip}')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.get('/api/health')
def health():
    redis_ok = False
    try:
        redis_client.ping()
        redis_ok = True
    except Exception:
        pass

    scala_ok   = _check_component_health(SCALA_HEALTH)
    elixir_ok  = _check_component_health(ELIXIR_METRICS_URL)
    cpp_ok     = _check_cpp_health()

    status = {
        'status':    'ok' if all([redis_ok, scala_ok]) else 'degraded',
        'component': 'python',
        'ts':        int(time.time()),
        'components': {
            'redis':  'ok' if redis_ok  else 'error',
            'scala':  'ok' if scala_ok  else 'error',
            'elixir': 'ok' if elixir_ok else 'error',
            'cpp':    'ok' if cpp_ok    else 'error',
        }
    }
    http_status = 200 if status['status'] == 'ok' else 503
    return jsonify(status), http_status

@app.get('/api/metrics')
@require_auth
def metrics():
    rule_count = len(_load_rules())
    session_count = len([k for k in redis_client.keys('session:*')])
    return jsonify({
        'component':     'python',
        'rule_count':    rule_count,
        'active_sessions': session_count,
        'ts':            int(time.time()),
    })

# ─────────────────────────────────────────────
# Serve the React SPA
# ─────────────────────────────────────────────

@app.get('/', defaults={'path': ''})
@app.get('/<path:path>')
def serve_spa(path):
    return app.send_static_file('app.html')

# ─────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('FLASK_PORT', 5000))
    log.info(f'Starting Flask on port {port}')
    app.run(host='0.0.0.0', port=port, debug=False)
