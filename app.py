from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import uuid
import os
from datetime import datetime

app = Flask(__name__, static_folder='static')
CORS(app)

DB_PATH = 'geotags.db'

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS tags (
        id TEXT PRIMARY KEY,
        lat REAL NOT NULL,
        lng REAL NOT NULL,
        label TEXT,
        note TEXT,
        category TEXT,
        created_at TEXT
    )''')
    db.commit()
    db.close()

init_db()

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/tags', methods=['GET'])
def get_tags():
    db = get_db()
    rows = db.execute('SELECT * FROM tags ORDER BY created_at DESC').fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/tags', methods=['POST'])
def add_tag():
    data = request.get_json()
    if not data or 'lat' not in data or 'lng' not in data:
        return jsonify({'error': 'lat and lng required'}), 400
    tag = {
        'id': str(uuid.uuid4()),
        'lat': float(data['lat']),
        'lng': float(data['lng']),
        'label': data.get('label', 'Untitled'),
        'note': data.get('note', ''),
        'category': data.get('category', 'general'),
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    db = get_db()
    db.execute('INSERT INTO tags VALUES (:id,:lat,:lng,:label,:note,:category,:created_at)', tag)
    db.commit()
    db.close()
    return jsonify(tag), 201

@app.route('/api/tags/<tag_id>', methods=['DELETE'])
def delete_tag(tag_id):
    db = get_db()
    cur = db.execute('DELETE FROM tags WHERE id=?', (tag_id,))
    db.commit()
    db.close()
    if cur.rowcount == 0:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'deleted': tag_id})

@app.route('/api/tags/<tag_id>', methods=['PUT'])
def update_tag(tag_id):
    data = request.get_json()
    db = get_db()
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

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)
