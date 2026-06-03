from flask import Flask, request, jsonify, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Issue 01: Hardcoded secret key (security vulnerability)
app.secret_key = "mysecretkey123"

# Issue 2: Hardcoded database path with no config management
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            email TEXT
        )
    """)
    conn.commit()
    conn.close()

# Issue 3: Passwords stored in plain text
def add_user(username, password, email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        (username, password, email)
    )
    conn.commit()
    conn.close()

# Issue 4: SQL Injection vulnerability — raw string formatting in query
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Vulnerable: should use parameterized query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({"message": "Login successful", "user_id": user[0]})
    return jsonify({"message": "Invalid credentials"}), 401


# 
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")
    add_user(username, password, email)
    return jsonify({"message": "User registered"}), 201


# Issue 6: Exposes all user data including passwords
@app.route("/users", methods=["GET"])
def get_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    # Returns raw tuples including passwords — sensitive data exposure
    return jsonify({"users": users})


# Issue 7: Debug mode enabled in production-style code
@app.route("/debug", methods=["GET"])
def debug_info():
    return jsonify({
        "db_path": DB_PATH,
        "secret_key": app.secret_key,
        "env": dict(os.environ)   # Exposes all environment variables
    })


# Issue 8: No error handling — crashes on bad input
@app.route("/user/<user_id>", methods=["GET"])
def get_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # Another SQL injection
    user = cursor.fetchone()
    conn.close()
    return jsonify({"user": user})


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Flask Demo App</title></head>
<body>
  <h1>Flask Demo App</h1>
  <h2>Register</h2>
  <form action="/register" method="POST">
    Username: <input name="username"><br>
    Password: <input type="password" name="password"><br>
    Email: <input name="email"><br>
    <button type="submit">Register</button>
  </form>
  <h2>Login</h2>
  <form action="/login" method="POST">
    Username: <input name="username"><br>
    Password: <input type="password" name="password"><br>
    <button type="submit">Login</button>
  </form>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


if __name__ == "__main__":
    init_db()
    # Issue 9: debug=True should never be used in production
    app.run(debug=True, host="0.0.0.0", port=5000)
