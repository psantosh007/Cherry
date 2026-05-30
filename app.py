"""
CherryTag backend — Flask + SQLite + AWS IoT MQTT (paho-mqtt over TLS)
                 + user auth (sign-up / sign-in / sign-out)
                 + rewards system (points, QR redemption)

Render env vars required:
  AWS_IOT_ENDPOINT   – e.g. xxxxxx-ats.iot.us-east-1.amazonaws.com
  AWS_IOT_CERT       – full contents of device certificate .pem  (multi-line ok)
  AWS_IOT_KEY        – full contents of private key .pem
  AWS_IOT_CA         – full contents of AmazonRootCA1.pem
  AWS_IOT_CLIENT_ID  – (optional) defaults to "cherry-<random>"
  SECRET_KEY         – random string for Flask sessions

MQTT topic map
──────────────
PUBLISH  (server → AWS IoT)
  cherry/user/{user_id}/email              – email address on signup/signin
  cherry/user/{user_id}/qr/scanned         – decoded QR payload when user scans a code
  cherry/user/{user_id}/pin/new            – new geo-pin created
  cherry/user/{user_id}/pin/deleted        – geo-pin deleted
  cherry/rewards/updated                   – broadcast whenever any reward changes

SUBSCRIBE  (AWS IoT → server)
  cherry/user/+/rewards/set                – set absolute points for a user
  cherry/user/+/rewards/add                – add delta points for a user
  cherry/user/+/qr/issue                   – issue / refresh a user's reward QR code
  cherry/admin/commands                    – admin commands
  cherry/broadcast/#                       – general broadcast
"""

from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
import sqlite3, uuid, os, json, threading, tempfile, hashlib, hmac, secrets
from datetime import datetime

# ── MQTT ──────────────────────────────────────────────────────────────────────
MQTT_ENABLED = False
_mqtt_client = None
_mqtt_lock   = threading.Lock()


def _write_tmp_pem(env_key: str) -> str | None:
    """Write a PEM env-var to a temp file; return path or None."""
    val = os.environ.get(env_key, '').strip()
    if not val:
        return None
    val = val.replace('\\n', '\n')          # Render flattens newlines
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='w')
    tmp.write(val)
    tmp.close()
    return tmp.name


# ── Inbound MQTT handler ──────────────────────────────────────────────────────
def _handle_rewards_set(user_id: str, data: dict):
    """cherry/user/{user_id}/rewards/set  →  { points: <int> }"""
    points = data.get('points')
    if points is None:
        print(f'[MQTT] rewards/set missing points for {user_id}')
        return
    db = get_db()
    db.execute('UPDATE users SET reward_points=? WHERE id=?', (int(points), user_id))
    db.commit()
    row = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    db.close()
    if row:
        print(f'[MQTT] rewards/set → user {user_id} points={points}')
        mqtt_publish('cherry/rewards/updated', {
            'event':   'rewards_set',
            'user_id': user_id,
            'points':  int(points),
            'ts':      _now(),
        })


def _handle_rewards_add(user_id: str, data: dict):
    """cherry/user/{user_id}/rewards/add  →  { delta: <int> }"""
    delta = data.get('delta', 0)
    db = get_db()
    db.execute(
        'UPDATE users SET reward_points = MAX(0, reward_points + ?) WHERE id=?',
        (int(delta), user_id)
    )
    db.commit()
    row = db.execute('SELECT id, reward_points FROM users WHERE id=?', (user_id,)).fetchone()
    db.close()
    if row:
        new_pts = row['reward_points']
        print(f'[MQTT] rewards/add → user {user_id} delta={delta} new={new_pts}')
        mqtt_publish('cherry/rewards/updated', {
            'event':   'rewards_add',
            'user_id': user_id,
            'delta':   int(delta),
            'points':  new_pts,
            'ts':      _now(),
        })


def _handle_qr_issue(user_id: str, data: dict):
    """cherry/user/{user_id}/qr/issue  →  issues / refreshes reward QR token."""
    token = secrets.token_urlsafe(24)
    db = get_db()
    db.execute('UPDATE users SET reward_qr_token=? WHERE id=?', (token, user_id))
    db.commit()
    row = db.execute('SELECT email, nickname FROM users WHERE id=?', (user_id,)).fetchone()
    db.close()
    if row:
        print(f'[MQTT] qr/issue → user {user_id} new token issued')
        mqtt_publish(f'cherry/user/{user_id}/qr/issued', {
            'event':   'qr_issued',
            'user_id': user_id,
            'token':   token,
            'ts':      _now(),
        })


def _mqtt_on_connect(client, userdata, flags, rc, properties=None):
    global MQTT_ENABLED
    if rc == 0:
        MQTT_ENABLED = True
        print('[MQTT] Connected to AWS IoT Core')
        topics = [
            ('cherry/user/+/rewards/set',  1),
            ('cherry/user/+/rewards/add',  1),
            ('cherry/user/+/qr/issue',     1),
            ('cherry/admin/commands',       1),
            ('cherry/broadcast/#',          1),
        ]
        for topic, qos in topics:
            client.subscribe(topic, qos=qos)
            print(f'[MQTT] Subscribed → {topic}')
    else:
        print(f'[MQTT] Connect failed rc={rc}')


def _mqtt_on_disconnect(client, userdata, rc, properties=None):
    global MQTT_ENABLED
    MQTT_ENABLED = False
    print(f'[MQTT] Disconnected rc={rc}')


def _mqtt_on_message(client, userdata, msg):
    topic = msg.topic
    try:
        data = json.loads(msg.payload.decode())
        print(f'[MQTT] ← {topic}: {data}')
    except Exception as e:
        print(f'[MQTT] Decode error on {topic}: {e}')
        return

    parts = topic.split('/')   # cherry / user / {user_id} / action / sub

    # cherry/user/{user_id}/rewards/set
    if len(parts) == 5 and parts[0] == 'cherry' and parts[1] == 'user' \
            and parts[3] == 'rewards' and parts[4] == 'set':
        _handle_rewards_set(parts[2], data)

    # cherry/user/{user_id}/rewards/add
    elif len(parts) == 5 and parts[0] == 'cherry' and parts[1] == 'user' \
            and parts[3] == 'rewards' and parts[4] == 'add':
        _handle_rewards_add(parts[2], data)

    # cherry/user/{user_id}/qr/issue
    elif len(parts) == 5 and parts[0] == 'cherry' and parts[1] == 'user' \
            and parts[3] == 'qr' and parts[4] == 'issue':
        _handle_qr_issue(parts[2], data)

    # cherry/admin/commands
    elif topic == 'cherry/admin/commands':
        print(f'[MQTT] Admin cmd: {data.get("cmd")}')


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
        client.tls_set(ca_certs=ca_path, certfile=cert_path, keyfile=key_path)
        client.on_connect    = _mqtt_on_connect
        client.on_disconnect = _mqtt_on_disconnect
        client.on_message    = _mqtt_on_message

        client.connect(endpoint, port=8883, keepalive=30)
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


# ── FLASK ─────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

CORS(app, resources={r"/api/*": {
    "origins": ["https://cherry-egux.onrender.com"],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"],
    "supports_credentials": True,
}})


@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        return '', 204


# ── HELPERS ───────────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.utcnow().isoformat() + 'Z'


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
        id               TEXT PRIMARY KEY,
        email            TEXT UNIQUE NOT NULL,
        nickname         TEXT NOT NULL,
        pw_hash          TEXT NOT NULL,
        salt             TEXT NOT NULL,
        created_at       TEXT NOT NULL,
        reward_points    INTEGER NOT NULL DEFAULT 0,
        reward_qr_token  TEXT
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

    db.execute('''CREATE TABLE IF NOT EXISTS qr_scans (
        id          TEXT PRIMARY KEY,
        user_id     TEXT,
        scanned_at  TEXT NOT NULL,
        raw_payload TEXT NOT NULL,
        tag_id      TEXT,
        tag_label   TEXT,
        tag_lat     REAL,
        tag_lng     REAL
    )''')

    # Safe migrations for older schemas
    migrations = [
        "ALTER TABLE tags ADD COLUMN owner TEXT",
        "ALTER TABLE tags ADD COLUMN user_id TEXT",
        "ALTER TABLE users ADD COLUMN reward_points INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN reward_qr_token TEXT",
    ]
    for sql in migrations:
        try:
            db.execute(sql)
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
    db  = get_db()
    row = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    db.close()
    return dict(row) if row else None


def user_public(u: dict) -> dict:
    return {
        'id':              u['id'],
        'email':           u['email'],
        'nickname':        u['nickname'],
        'reward_points':   u.get('reward_points', 0),
        'reward_qr_token': u.get('reward_qr_token'),
    }


# ── AUTH ROUTES ───────────────────────────────────────────────────────────────
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data     = request.get_json() or {}
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
    now     = _now()
    # Issue a reward QR token at account creation
    reward_qr_token = secrets.token_urlsafe(24)

    db = get_db()
    try:
        db.execute(
            'INSERT INTO users VALUES (?,?,?,?,?,?,?,?)',
            (uid, email, nickname, pw_hash, salt, now, 0, reward_qr_token)
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'error': 'email already registered'}), 409
    db.close()

    session['user_id'] = uid

    # ── Publish: email identity
    mqtt_publish(f'cherry/user/{uid}/email', {
        'event':    'user_signup',
        'user_id':  uid,
        'email':    email,
        'nickname': nickname,
        'ts':       now,
    })

    # ── Publish: initial QR token issued
    mqtt_publish(f'cherry/user/{uid}/qr/issued', {
        'event':   'qr_issued',
        'user_id': uid,
        'token':   reward_qr_token,
        'ts':      now,
    })

    return jsonify({'user': {
        'id': uid, 'email': email, 'nickname': nickname,
        'reward_points': 0, 'reward_qr_token': reward_qr_token,
    }}), 201


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
    now = _now()

    # ── Publish: email identity on every sign-in
    mqtt_publish(f'cherry/user/{row["id"]}/email', {
        'event':    'user_signin',
        'user_id':  row['id'],
        'email':    email,
        'nickname': row['nickname'],
        'ts':       now,
    })

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


# ── REWARDS ROUTES ────────────────────────────────────────────────────────────
@app.route('/api/rewards', methods=['GET'])
def get_rewards():
    """Return current user's reward points and QR token."""
    u = current_user()
    if not u:
        return jsonify({'error': 'not authenticated'}), 401
    return jsonify({
        'user_id':         u['id'],
        'reward_points':   u.get('reward_points', 0),
        'reward_qr_token': u.get('reward_qr_token'),
    })


@app.route('/api/rewards/<user_id>', methods=['GET'])
def get_rewards_by_user(user_id):
    """Fetch rewards for a specific user_id (admin / internal use)."""
    db  = get_db()
    row = db.execute(
        'SELECT id, email, nickname, reward_points, reward_qr_token FROM users WHERE id=?',
        (user_id,)
    ).fetchone()
    db.close()
    if not row:
        return jsonify({'error': 'user not found'}), 404
    return jsonify(dict(row))


@app.route('/api/rewards/<user_id>', methods=['PUT'])
def update_rewards(user_id):
    """
    Update reward_points and/or reward_qr_token for a user.
    Body: { points?: int, delta?: int, new_qr?: bool }
    """
    data = request.get_json() or {}
    db   = get_db()
    row  = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'user not found'}), 404

    new_points = row['reward_points']
    new_token  = row['reward_qr_token']

    if 'points' in data:
        new_points = max(0, int(data['points']))
    elif 'delta' in data:
        new_points = max(0, new_points + int(data['delta']))

    if data.get('new_qr'):
        new_token = secrets.token_urlsafe(24)

    db.execute(
        'UPDATE users SET reward_points=?, reward_qr_token=? WHERE id=?',
        (new_points, new_token, user_id)
    )
    db.commit()
    db.close()

    now = _now()
    # ── Publish reward update
    mqtt_publish('cherry/rewards/updated', {
        'event':   'rewards_updated',
        'user_id': user_id,
        'points':  new_points,
        'ts':      now,
    })
    if data.get('new_qr'):
        mqtt_publish(f'cherry/user/{user_id}/qr/issued', {
            'event':   'qr_issued',
            'user_id': user_id,
            'token':   new_token,
            'ts':      now,
        })

    return jsonify({
        'user_id':         user_id,
        'reward_points':   new_points,
        'reward_qr_token': new_token,
    })


# ── QR SCAN ROUTE ─────────────────────────────────────────────────────────────
@app.route('/api/qr/scan', methods=['POST'])
def record_qr_scan():
    """
    Called by the frontend when a QR code is decoded.
    Body: { raw_payload: str }

    • Persists the scan to qr_scans table.
    • Publishes cherry/user/{user_id}/qr/scanned with the decoded data.
    • Awards 10 points per scan to the scanning user.
    Returns the scan record + updated reward points.
    """
    data        = request.get_json() or {}
    raw_payload = (data.get('raw_payload') or '').strip()
    if not raw_payload:
        return jsonify({'error': 'raw_payload required'}), 400

    u   = current_user()
    uid = u['id'] if u else None
    now = _now()

    # Try to parse as a CherryTag JSON pin
    tag_id = tag_label = tag_lat = tag_lng = None
    try:
        parsed = json.loads(raw_payload)
        tag_id    = parsed.get('id')
        tag_label = parsed.get('label')
        tag_lat   = parsed.get('lat')
        tag_lng   = parsed.get('lng')
    except (json.JSONDecodeError, AttributeError):
        parsed = {'raw': raw_payload}

    scan_id = str(uuid.uuid4())
    db = get_db()
    db.execute(
        'INSERT INTO qr_scans VALUES (?,?,?,?,?,?,?,?)',
        (scan_id, uid, now, raw_payload, tag_id, tag_label, tag_lat, tag_lng)
    )

    # Award points to authenticated user
    new_points = None
    if uid:
        db.execute(
            'UPDATE users SET reward_points = reward_points + 10 WHERE id=?',
            (uid,)
        )
        row = db.execute(
            'SELECT reward_points FROM users WHERE id=?', (uid,)
        ).fetchone()
        new_points = row['reward_points'] if row else None

    db.commit()
    db.close()

    # ── Publish: scanned QR payload
    mqtt_payload = {
        'event':       'qr_scanned',
        'scan_id':     scan_id,
        'user_id':     uid,
        'raw_payload': raw_payload,
        'parsed':      parsed,
        'ts':          now,
    }
    topic = f'cherry/user/{uid}/qr/scanned' if uid else 'cherry/qr/scanned/anonymous'
    mqtt_publish(topic, mqtt_payload)

    # ── Publish: points update
    if uid and new_points is not None:
        mqtt_publish('cherry/rewards/updated', {
            'event':   'scan_reward',
            'user_id': uid,
            'delta':   10,
            'points':  new_points,
            'ts':      now,
        })

    return jsonify({
        'scan_id':       scan_id,
        'user_id':       uid,
        'parsed':        parsed,
        'reward_points': new_points,
        'ts':            now,
    }), 201


@app.route('/api/qr/scans', methods=['GET'])
def list_qr_scans():
    """Return scan history for the current user."""
    u = current_user()
    if not u:
        return jsonify({'error': 'not authenticated'}), 401
    db   = get_db()
    rows = db.execute(
        'SELECT * FROM qr_scans WHERE user_id=? ORDER BY scanned_at DESC LIMIT 50',
        (u['id'],)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


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
        'created_at': _now(),
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

    topic = f'cherry/user/{uid}/pin/new' if uid else 'cherry/pin/new/anonymous'
    mqtt_publish(topic, {'event': 'pin_created', 'tag': tag, 'ts': tag['created_at']})
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
        uid   = row['user_id']
        topic = f'cherry/user/{uid}/pin/deleted' if uid else 'cherry/pin/deleted/anonymous'
        mqtt_publish(topic, {
            'event':   'pin_deleted',
            'tag_id':  tag_id,
            'label':   row['label'],
            'ts':      _now(),
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


# ── STATUS ────────────────────────────────────────────────────────────────────
@app.route('/api/mqtt/status', methods=['GET'])
def mqtt_status():
    return jsonify({'mqtt_enabled': MQTT_ENABLED})


if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)
