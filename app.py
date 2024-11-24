from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__, template_folder="templates")
app.secret_key = "your_secret_key"  # Replace with a secure key

# Helper: Check user credentials
def validate_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, is_admin FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.checkpw(password.encode(), user[2].encode()):
        return {"id": user[0], "username": user[1], "is_admin": user[3]}
    return None

# Route: Home Page
@app.route("/")
def home():
    if "user" in session:
        user = session["user"]
        if user["is_admin"]:
            return redirect(url_for("admin_dashboard"))
        return f"Welcome, {user['username']}! <a href='/logout'>Logout</a>"
    return render_template("login.html")

# Route: Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user = validate_user(username, password)
        if user:
            session["user"] = user
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html")

# Route: Register
@app.route("/register", methods=["GET", "POST"])
def register():
    logging.debug("Entered /register route")
    if request.method == "POST":
        try:
            username = request.form["username"]
            password = request.form["password"]
            logging.debug(f"Attempting to register user: {username}")
            
            if not username or not password:
                flash("All fields are required.", "danger")
                return redirect(url_for("register"))
            
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            
            # Insert into the database
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            
            flash("Registration successful!", "success")
            return redirect(url_for("login"))
        except Exception as e:
            logging.error(f"Error during registration: {e}")
            flash("An error occurred. Please try again.", "danger")
            return redirect(url_for("register"))
    return render_template("register.html")


# Route: Admin Dashboard
@app.route("/admin")
def admin_dashboard():
    if "user" not in session or not session["user"]["is_admin"]:
        flash("Access denied.", "danger")
        return redirect(url_for("home"))
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, is_admin FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return render_template("admin.html", users=users)

# Route: Logout
@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out successfully.", "success")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)

