from flask import Flask, jsonify, request
import uuid

app = Flask(__name__)

# Хранилище состояний в памяти
storage = {}

@app.route('/state/init', methods=['GET'])
def init_state():
    # Генерируем уникальный ID
    new_id = str(uuid.uuid4())
    storage[new_id] = {"status": "INITIALIZED"}
    return jsonify({"id": new_id}), 200

@app.route('/state/set', methods=['POST'])
def set_state():
    req_id = request.headers.get("X-Request-Id")
    if not req_id or req_id not in storage:
        return jsonify({"error": "ID not found or invalid"}), 404
    
    data = request.get_json(silent=True)
    if not data or "theme" not in data or "person" not in data:
        return jsonify({"error": "Invalid body"}), 400

    storage[req_id]["theme"] = data["theme"]
    storage[req_id]["person"] = data["person"]
    storage[req_id]["status"] = "DATA_RECEIVED"
    return jsonify({"status": "SUCCESS", "message": "Data saved"}), 200

@app.route('/state/status', methods=['POST'])
def status_state():
    data = request.get_json(silent=True) or {}
    req_id = data.get("id")
    if not req_id or req_id not in storage:
        return jsonify({"error": "State not found"}), 404

    return jsonify(storage[req_id]), 200

if __name__ == '__main__':
    # Запуск ровно на порту 5157
    app.run(host='127.0.0.1', port=5157, debug=False)