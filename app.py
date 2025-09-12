from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change this
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.route("/")
def home():
    if "user_id" in session:
        return f"Welcome back, {session['user_email']}!"
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        pw = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, pw):
            session["user_id"] = user.id
            session["user_email"] = user.email
            flash("✅ Login successful", "success")
            return redirect(url_for("home"))
        else:
            flash("❌ Invalid email or password", "danger")

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        pw = request.form.get("password")

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("❌ Email already registered", "warning")
        else:
            hashed_pw = bcrypt.generate_password_hash(pw).decode("utf-8")
            new_user = User(email=email, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash("✅ Account created, please login", "success")
            return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("✅ Logged out", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
