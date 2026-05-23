from flask import Flask, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

logging.basicConfig(level=logging.INFO)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["50 per minute"]
)

USERS = {
    "user": {"password": "user123", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"}
}

NOTES = {
    "user": ["User note: test data"],
    "admin": ["Admin note: sensitive system data"]
}


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.route("/")
def home():
    return jsonify({
        "app": "Secure Notes",
        "status": "running",
        "security": "enabled",
        "endpoints": ["/login", "/data", "/admin", "/logout", "/health"]
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    ip = request.remote_addr

    logging.info(f"LOGIN_ATTEMPT user={username} ip={ip}")

    user = USERS.get(username)

    if not user or user["password"] != password:
        logging.warning(f"LOGIN_FAILED user={username} ip={ip}")
        return jsonify({"error": "Invalid credentials"}), 401

    session["username"] = username
    session["role"] = user["role"]

    logging.info(f"LOGIN_SUCCESS user={username} role={user['role']} ip={ip}")
    return jsonify({"message": "Logged in", "role": user["role"]})


@app.route("/data")
def data():
    username = session.get("username")

    if not username:
        logging.warning(f"UNAUTHORIZED_DATA_ACCESS ip={request.remote_addr}")
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "user": username,
        "notes": NOTES.get(username, [])
    })


@app.route("/admin")
def admin():
    username = session.get("username")
    role = session.get("role")

    logging.info(f"ADMIN_ACCESS_ATTEMPT user={username} role={role} ip={request.remote_addr}")

    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    if role != "admin":
        logging.warning(f"FORBIDDEN_ADMIN_ACCESS user={username} role={role}")
        return jsonify({"error": "Forbidden - admin only"}), 403

    return jsonify({
        "message": "Welcome admin",
        "secret_data": "Secure Notes admin panel"
    })


@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f"RATE_LIMIT ip={request.remote_addr}")
    return jsonify({"error": "Too many requests"}), 429


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
