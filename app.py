from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change this
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# -------------------- MODELS --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    must_change_password = db.Column(db.Boolean, default=True)  # Force reset on first login
    is_admin = db.Column(db.Boolean, default=False)  # Optional, if you want admin accounts

# -------------------- ROUTES --------------------
@app.route("/")
def home():
    if "user_id" in session:
        return f"Welcome back, {session['user_email']}!"
    return redirect(url_for("login"))

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        pw = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, pw):
            session["user_id"] = user.id
            session["user_email"] = user.email

            if user.must_change_password:
                flash("⚠️ You must set a new password before continuing", "warning")
                return redirect(url_for("change_password"))

            flash("✅ Login successful", "success")
            return redirect(url_for("home"))
        else:
            flash("❌ Invalid email or password", "danger")

    return render_template("login.html")

# ADMIN SIGNUP (register employees)
@app.route("/signup", methods=["GET", "POST"])
def signup():
    # you could add: if not current_user.is_admin: abort(403)
    if request.method == "POST":
        email = request.form.get("email")
        temp_pw = request.form.get("password")  # Admin chooses or generates temporary password

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("❌ Email already registered", "warning")
        else:
            hashed_pw = bcrypt.generate_password_hash(temp_pw).decode("utf-8")
            new_user = User(email=email, password=hashed_pw, must_change_password=True)
            db.session.add(new_user)
            db.session.commit()
            flash(f"✅ User {email} created with temporary password", "success")
            return redirect(url_for("signup"))

    return render_template("signup.html")

# CHANGE PASSWORD (for first login or reset)
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if request.method == "POST":
        new_pw = request.form.get("new_password")
        confirm_pw = request.form.get("confirm_password")

        if new_pw != confirm_pw:
            flash("❌ Passwords do not match", "danger")
            return redirect(url_for("change_password"))

        user.password = bcrypt.generate_password_hash(new_pw).decode("utf-8")
        user.must_change_password = False
        db.session.commit()
        flash("✅ Password updated successfully", "success")
        return redirect(url_for("home"))

    return render_template("change_password.html")

# LOGOUT
@app.route("/home")
def dashboard():
    if "user_id" in session:
        return render_template("home.html")
    return redirect(url_for("login"))

# -------------------- MAIN --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)