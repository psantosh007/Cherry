"""
CherryTag backend — Flask + SQLite + AWS IoT MQTT (paho-mqtt over TLS)
                 + user auth (sign-up / sign-in / sign-out)

Render env vars required:
  AWS_IOT_ENDPOINT   – e.g. xxxxxx-ats.iot.us-east-1.amazonaws.com
  AWS_IOT_CERT       – full contents of device certificate .pem  (multi-line ok)
  AWS_IOT_KEY        – full contents of private key .pem
  AWS_IOT_CA         – full contents of AmazonRootCA1.pem
  AWS_IOT_CLIENT_ID  – (optional) defaults to "cherry-<random>"
  SECRET_KEY         – random string for Flask sessions
"""

from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
import sqlite3, uuid, os, json, threading, tempfile, hashlib, hmac, secrets
from datetime import datetime

# ── AWS IoT MQTT via paho-mqtt (pure Python — works on Render) ───────────────
# pip install paho-mqtt
# Certificates are stored in Render env vars as full PEM strings.
# We write them to temp files at startup so paho can read them.

MQTT_ENABLED   = False
_mqtt_client   = None
_mqtt_lock     = threading.Lock()

def _write_tmp_pem(env_key: str) -> str | None:
    """Write a PEM env-var to a temp file; return path or None."""
    val = os.environ.get(env_key, '').strip()
    if not val:
        return None
    # Render stores multi-line secrets with literal \n – normalise
    val = val.replace('\\n', '\n')
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='w')
    tmp.write(val)
    tmp.close()
    return tmp.name

def _mqtt_on_connect(client, userdata, flags, rc, properties=None):
    global MQTT_ENABLED
    if rc == 0:
        MQTT_ENABLED = True
        print('[MQTT] Connected to AWS IoT Core')
        for topic in ('geotag/broadcast/#', 'geotag/admin/commands'):
            client.subscribe(topic, qos=1)
            print(f'[MQTT] Subscribed → {topic}')
    else:
        print(f'[MQTT] Connect failed rc={rc}')

def _mqtt_on_disconnect(client, userdata, rc, properties=None):
    global MQTT_ENABLED
    MQTT_ENABLED = False
    print(f'[MQTT] Disconnected rc={rc}')

def _mqtt_on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        print(f'[MQTT] ← {msg.topic}: {data}')
        if msg.topic == 'geotag/admin/commands':
            cmd = data.get('cmd')
            print(f'[MQTT] Admin cmd: {cmd}')
    except Exception as e:
        print(f'[MQTT] Message error: {e}')

def _start_mqtt():
    global _mqtt_client
    endpoint  = os.environ.get('AWS_IOT_ENDPOINT', '').strip()
    client_id = os.environ.get('AWS_IOT_CLIENT_ID',
                               f'cherry-{uuid.uuid4().hex[:8]}')

    cert_path = _write_tmp_pem('AWS_IOT_CERT')
    key_path  = _write_tmp_pem('AWS_IOT_KEY')
    ca_path   = _write_tmp_pem('AWS_IOT_CA')

    if not all([endpoint, cert_path, key_path, ca_path]):
        print('[MQTT] Missing env vars — MQTT disabled')
        return

    try:
        import paho.mqtt.client as mqtt_lib

        client = mqtt_lib.Client(
            client_id=client_id,
            protocol=mqtt_lib.MQTTv5,
        )
        client.tls_set(
            ca_certs=ca_path,
            certfile=cert_path,
            keyfile=key_path,
        )
        client.on_connect    = _mqtt_on_connect
        client.on_disconnect = _mqtt_on_disconnect
        client.on_message    = _mqtt_on_message

        # AWS IoT port 8883 – standard MQTT over TLS
        client.connect(endpoint, port=8883, keepalive=30)

        # run_forever in a daemon thread so Gunicorn can still start
        t = threading.Thread(target=client.loop_forever, daemon=True)
        t.start()

        _mqtt_client = client
        print('[MQTT] paho client started')

    except ImportError:
        print('[MQTT] paho-mqtt not installed — MQTT disabled')
    except Exception as e:
        print(f'[MQTT] Startup error: {e}')

_start_mqtt()

def mqtt_publish(topic: str, payload: dict):
    """Non-blocking publish; silently skips if MQTT unavailable."""
    if not MQTT_ENABLED or _mqtt_client is None:
        return
    try:
        with _mqtt_lock:
            _mqtt_client.publish(topic, json.dumps(payload), qos=1)
    except Exception as e:
        print(f'[MQTT] Publish error on {topic}: {e}')

def user_topic(nickname_or_email: str) -> str:
    safe = (nickname_or_email
            .replace('@', '_at_')
            .replace('.', '_')
            .replace('+', '_')
            .replace(' ', '_'))
    return f'geotag/user/{safe}'

# ── FLASK ─────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

CORS(app, resources={r"/api/*": {
    "origins": ["https://cherry-egux.onrender.com"],
    "methods": ["GET","POST","PUT","DELETE","OPTIONS"],
    "allow_headers": ["Content-Type","Authorization"],
    "supports_credentials": True,
}})

@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        return '', 204

# ── DATABASE ──────────────────────────────────────────────────────────────────
DB_PATH = 'geotags.db'

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    return db

def _hash_pw(password: str, salt: str) -> str:
    return hmac.new(
        salt.encode(), password.encode(), hashlib.sha256
    ).hexdigest()

def init_db():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id         TEXT PRIMARY KEY,
        email      TEXT UNIQUE NOT NULL,
        nickname   TEXT NOT NULL,
        pw_hash    TEXT NOT NULL,
        salt       TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS tags (
        id         TEXT PRIMARY KEY,
        lat        REAL NOT NULL,
        lng        REAL NOT NULL,
        label      TEXT,
        note       TEXT,
        category   TEXT,
        created_at TEXT,
        owner      TEXT,
        user_id    TEXT
    )''')
    # Safe migrations
    for col in (
        "ALTER TABLE tags ADD COLUMN owner TEXT",
        "ALTER TABLE tags ADD COLUMN user_id TEXT",
    ):
        try:
            db.execute(col)
        except sqlite3.OperationalError:
            pass
    db.commit()
    db.close()

init_db()

# ── AUTH helpers ──────────────────────────────────────────────────────────────
def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    db.close()
    return dict(row) if row else None

def user_public(u: dict) -> dict:
    return {'id': u['id'], 'email': u['email'], 'nickname': u['nickname']}

# ── AUTH ROUTES ───────────────────────────────────────────────────────────────
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    email    = (data.get('email') or '').strip().lower()
    nickname = (data.get('nickname') or '').strip()
    password = data.get('password') or ''

    if not email or not password or not nickname:
        return jsonify({'error': 'email, nickname and password required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'password must be ≥ 6 characters'}), 400

    salt    = secrets.token_hex(16)
    pw_hash = _hash_pw(password, salt)
    uid     = str(uuid.uuid4())
    now     = datetime.utcnow().isoformat() + 'Z'

    db = get_db()
    try:
        db.execute(
            'INSERT INTO users VALUES (?,?,?,?,?,?)',
            (uid, email, nickname, pw_hash, salt, now)
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'error': 'email already registered'}), 409
    db.close()

    session['user_id'] = uid

    # Announce new user over MQTT
    mqtt_publish(f'geotag/user/{user_topic(email)}/auth/signup', {
        'event': 'user_signup', 'nickname': nickname, 'ts': now
    })

    return jsonify({'user': {'id': uid, 'email': email, 'nickname': nickname}}), 201

@app.route('/api/auth/signin', methods=['POST'])
def signin():
    data     = request.get_json() or {}
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    db  = get_db()
    row = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    db.close()

    if not row:
        return jsonify({'error': 'invalid email or password'}), 401

    expected = _hash_pw(password, row['salt'])
    if not secrets.compare_digest(expected, row['pw_hash']):
        return jsonify({'error': 'invalid email or password'}), 401

    session['user_id'] = row['id']
    return jsonify({'user': user_public(dict(row))}), 200

@app.route('/api/auth/signout', methods=['POST'])
def signout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/auth/me', methods=['GET'])
def me():
    u = current_user()
    if not u:
        return jsonify({'user': None})
    return jsonify({'user': user_public(u)})

# ── TAGS ROUTES ───────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/tags', methods=['GET'])
def get_tags():
    db   = get_db()
    rows = db.execute('SELECT * FROM tags ORDER BY created_at DESC').fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/tags', methods=['POST'])
def add_tag():
    data = request.get_json()
    if not data or 'lat' not in data or 'lng' not in data:
        return jsonify({'error': 'lat and lng required'}), 400

    u     = current_user()
    owner = u['nickname'] if u else data.get('owner', 'anonymous')
    uid   = u['id'] if u else None

    tag = {
        'id':         str(uuid.uuid4()),
        'lat':        float(data['lat']),
        'lng':        float(data['lng']),
        'label':      data.get('label', 'Untitled'),
        'note':       data.get('note', ''),
        'category':   data.get('category', 'general'),
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'owner':      owner,
        'user_id':    uid,
    }
    db = get_db()
    db.execute(
        'INSERT INTO tags VALUES '
        '(:id,:lat,:lng,:label,:note,:category,:created_at,:owner,:user_id)',
        tag
    )
    db.commit()
    db.close()

    mqtt_publish(f'{user_topic(owner)}/pin/new', {
        'event': 'pin_created', 'tag': tag, 'ts': tag['created_at']
    })
    return jsonify(tag), 201

@app.route('/api/tags/<tag_id>', methods=['DELETE'])
def delete_tag(tag_id):
    db  = get_db()
    row = db.execute('SELECT * FROM tags WHERE id=?', (tag_id,)).fetchone()
    cur = db.execute('DELETE FROM tags WHERE id=?', (tag_id,))
    db.commit()
    db.close()

    if cur.rowcount == 0:
        return jsonify({'error': 'Not found'}), 404

    if row:
        owner = row['owner'] or 'anonymous'
        mqtt_publish(f'{user_topic(owner)}/pin/deleted', {
            'event': 'pin_deleted', 'tag_id': tag_id,
            'label': row['label'], 'ts': datetime.utcnow().isoformat() + 'Z'
        })
    return jsonify({'deleted': tag_id})

@app.route('/api/tags/<tag_id>', methods=['PUT'])
def update_tag(tag_id):
    data = request.get_json()
    db   = get_db()
    db.execute(
        'UPDATE tags SET label=?, note=?, category=? WHERE id=?',
        (data.get('label'), data.get('note'), data.get('category'), tag_id)
    )
    db.commit()
    row = db.execute('SELECT * FROM tags WHERE id=?', (tag_id,)).fetchone()
    db.close()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(row))

@app.route('/api/mqtt/status', methods=['GET'])
def mqtt_status():
    return jsonify({'mqtt_enabled': MQTT_ENABLED})

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)
