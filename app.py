"""Secure Student Management System with 2FA, RBAC, and encrypted storage."""
from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, Optional

import bleach
import jwt
import pyotp
from cryptography.fernet import Fernet
from flask import (
    Flask,
    Response,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from sqlalchemy import event
from wtforms import PasswordField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length


# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------


def _load_or_create_encryption_key(path: str = "secret.key") -> bytes:
    """Load an encryption key from disk or create a new one.

    In production this key must be stored in a secure secret manager or HSM.
    """

    env_key = os.getenv("ENCRYPTION_KEY")
    if env_key:
        return env_key.encode()

    if os.path.exists(path):
        with open(path, "rb") as file:
            return file.read()

    key = Fernet.generate_key()
    with open(path, "wb") as file:
        file.write(key)
    os.chmod(path, 0o600)
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET", secrets.token_hex(32)),
    SQLALCHEMY_DATABASE_URI="sqlite:///students.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    WTF_CSRF_TIME_LIMIT=None,
    JWT_SECRET=os.getenv("JWT_SECRET", secrets.token_hex(32)),
)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
fernet = Fernet(_load_or_create_encryption_key())


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

LOG_FILE = "activity.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default="student")
    password_hash = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(32), nullable=False, default=lambda: pyotp.random_base32())
    biometric_hash = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    students = db.relationship("Student", backref="creator", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)

    def set_biometric(self, biometric_phrase: str) -> None:
        self.biometric_hash = bcrypt.generate_password_hash(biometric_phrase).decode("utf-8")

    def check_biometric(self, biometric_phrase: str) -> bool:
        if not self.biometric_hash:
            return True
        return bcrypt.check_password_hash(self.biometric_hash, biometric_phrase)


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_payload = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def data(self) -> Dict[str, Any]:
        decrypted = decrypt_payload(self.encrypted_payload)
        return json.loads(decrypted)

    @data.setter
    def data(self, value: Dict[str, Any]) -> None:
        serialized = json.dumps(value)
        self.encrypted_payload = encrypt_payload(serialized)


# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    role = SelectField(
        "Role",
        choices=[("admin", "Admin"), ("teacher", "Teacher"), ("student", "Student")],
        validators=[DataRequired()],
    )
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    biometric_phrase = StringField(
        "Biometric Phrase",
        description="A secret phrase used as a stand-in for biometric authentication.",
        validators=[Length(max=120)],
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class TwoFactorForm(FlaskForm):
    otp_token = StringField("Authenticator OTP", validators=[DataRequired(), Length(min=6, max=6)])
    email_token = StringField("Email OTP", validators=[DataRequired(), Length(min=6, max=6)])
    biometric_phrase = StringField("Biometric Phrase", validators=[DataRequired(), Length(max=120)])
    submit = SubmitField("Verify")


class StudentForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired(), Length(max=100)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    grade = StringField("Grade", validators=[DataRequired(), Length(max=20)])
    notes = TextAreaField("Notes", validators=[Length(max=500)])
    submit = SubmitField("Save")


class APIAuthForm(FlaskForm):
    submit = SubmitField("Generate Token")


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def encrypt_payload(text: str) -> str:
    return fernet.encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_payload(token: str) -> str:
    return fernet.decrypt(token.encode("utf-8")).decode("utf-8")


def sanitize_text(text: str) -> str:
    return bleach.clean(text, strip=True)


def audit(action: str, details: str | None = None, user: Optional[User] = None) -> None:
    log_entry = ActivityLog(
        user_id=user.id if user else None,
        action=action,
        details=details,
        ip_address=request.remote_addr if request else None,
    )
    db.session.add(log_entry)
    db.session.commit()
    logger.info("%s - %s", action, details)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login first", "warning")
            return redirect(url_for("login"))
        if not session.get("two_factor_verified"):
            flash("Two-factor verification required", "warning")
            return redirect(url_for("two_factor"))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or user.role not in roles:
                flash("You do not have permission to access this resource", "danger")
                audit("unauthorized_access", f"Attempt to access {request.path}", user)
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def current_user() -> Optional[User]:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


@app.before_request
def load_logged_in_user() -> None:
    g.user = current_user()


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------


@app.route("/register", methods=["GET", "POST"])
@login_required
@role_required("admin")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        sanitized_username = sanitize_text(form.username.data)
        sanitized_email = sanitize_text(form.email.data)
        if User.query.filter((User.username == sanitized_username) | (User.email == sanitized_email)).first():
            flash("Username or email already taken", "danger")
            return render_template("register.html", form=form)

        user = User(
            username=sanitized_username,
            email=sanitized_email,
            role=form.role.data,
            otp_secret=pyotp.random_base32(),
        )
        user.set_password(form.password.data)
        if form.biometric_phrase.data:
            user.set_biometric(form.biometric_phrase.data)
        db.session.add(user)
        db.session.commit()
        audit("user_registered", f"User {user.username} registered", g.user)
        flash("User registered successfully", "success")
        return redirect(url_for("dashboard"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        sanitized_username = sanitize_text(form.username.data)
        user = User.query.filter_by(username=sanitized_username).first()
        if not user or not user.check_password(form.password.data):
            flash("Invalid credentials", "danger")
            audit("login_failed", f"Failed login for {sanitized_username}")
            return render_template("login.html", form=form)
        if not user.is_active:
            flash("Account is disabled", "danger")
            return render_template("login.html", form=form)
        session.clear()
        session["user_id"] = user.id
        session["email_otp"] = _send_email_otp(user)
        session["email_otp_expiry"] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        session["two_factor_verified"] = False
        flash("An OTP has been sent to your email", "info")
        audit("login_password_success", f"User {user.username} passed password stage", user)
        return redirect(url_for("two_factor"))
    return render_template("login.html", form=form)


def _send_email_otp(user: User) -> str:
    otp = f"{secrets.randbelow(10**6):06d}"
    # In a production environment, integrate with an email provider.
    logger.info("Sending OTP %s to %s", otp, user.email)
    print(f"[Email OTP] Send {otp} to {user.email}")
    return otp


@app.route("/two-factor", methods=["GET", "POST"])
def two_factor():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    form = TwoFactorForm()
    user = current_user()
    if not user:
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for("login"))

    qr_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(name=user.email, issuer_name="Secure SMS")

    if form.validate_on_submit():
        email_token = form.email_token.data
        otp_token = form.otp_token.data
        biometric_phrase = form.biometric_phrase.data

        expiry_str = session.get("email_otp_expiry")
        if not expiry_str or datetime.fromisoformat(expiry_str) < datetime.utcnow():
            flash("Email OTP expired. Please login again.", "danger")
            session.clear()
            return redirect(url_for("login"))

        if email_token != session.get("email_otp"):
            flash("Invalid email OTP", "danger")
            audit("email_otp_failed", "Incorrect email OTP", user)
            return render_template("two_factor.html", form=form, qr_uri=qr_uri)

        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(otp_token, valid_window=1):
            flash("Invalid authenticator OTP", "danger")
            audit("totp_failed", "Incorrect authenticator OTP", user)
            return render_template("two_factor.html", form=form, qr_uri=qr_uri)

        if not user.check_biometric(biometric_phrase):
            flash("Biometric verification failed", "danger")
            audit("biometric_failed", "Biometric mismatch", user)
            return render_template("two_factor.html", form=form, qr_uri=qr_uri)

        session["two_factor_verified"] = True
        session.pop("email_otp", None)
        session.pop("email_otp_expiry", None)
        audit("login_success", f"User {user.username} fully authenticated", user)
        flash("Authentication successful", "success")
        return redirect(url_for("dashboard"))

    return render_template("two_factor.html", form=form, qr_uri=qr_uri)


@app.route("/logout")
@login_required
def logout():
    user = current_user()
    audit("logout", "User logged out", user)
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Student management routes
# ---------------------------------------------------------------------------


@app.route("/")
@login_required
def dashboard():
    students = Student.query.all()
    decrypted_students = []
    for student in students:
        payload = student.data
        payload["id"] = student.id
        decrypted_students.append(payload)
    audit("view_dashboard", "Dashboard accessed", g.user)
    grade_distribution = _grade_distribution(decrypted_students)
    return render_template(
        "dashboard.html",
        students=decrypted_students,
        grade_distribution=grade_distribution,
        api_form=APIAuthForm(),
    )


def _grade_distribution(students: list[Dict[str, Any]]) -> Dict[str, int]:
    distribution: Dict[str, int] = {}
    for student in students:
        grade = student.get("grade", "Unknown")
        distribution[grade] = distribution.get(grade, 0) + 1
    return distribution


@app.route("/students/add", methods=["GET", "POST"])
@login_required
@role_required("admin", "teacher")
def add_student():
    form = StudentForm()
    if form.validate_on_submit():
        sanitized = {
            "full_name": sanitize_text(form.full_name.data),
            "email": sanitize_text(form.email.data),
            "grade": sanitize_text(form.grade.data),
            "notes": sanitize_text(form.notes.data or ""),
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }
        student = Student()
        student.data = sanitized
        student.creator = g.user
        db.session.add(student)
        db.session.commit()
        audit("student_created", f"Student {sanitized['full_name']} created", g.user)
        flash("Student added successfully", "success")
        return redirect(url_for("dashboard"))
    return render_template("student_form.html", form=form, action="Add")


@app.route("/students/<int:student_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "teacher")
def edit_student(student_id: int):
    student = Student.query.get_or_404(student_id)
    data = student.data
    form = StudentForm(data=data)
    if form.validate_on_submit():
        sanitized = {
            "full_name": sanitize_text(form.full_name.data),
            "email": sanitize_text(form.email.data),
            "grade": sanitize_text(form.grade.data),
            "notes": sanitize_text(form.notes.data or ""),
            "created_at": data.get("created_at"),
            "updated_at": datetime.utcnow().isoformat(),
        }
        student.data = sanitized
        db.session.commit()
        audit("student_updated", f"Student {sanitized['full_name']} updated", g.user)
        flash("Student updated successfully", "success")
        return redirect(url_for("dashboard"))
    return render_template("student_form.html", form=form, action="Update")


@app.route("/students/<int:student_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_student(student_id: int):
    student = Student.query.get_or_404(student_id)
    name = student.data.get("full_name", "Unknown")
    db.session.delete(student)
    db.session.commit()
    audit("student_deleted", f"Student {name} deleted", g.user)
    flash("Student deleted", "info")
    return redirect(url_for("dashboard"))


@app.route("/activity")
@login_required
@role_required("admin")
def view_activity():
    logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).all()
    return render_template("activity.html", logs=logs)


@app.route("/backup")
@login_required
@role_required("admin")
def backup_database() -> Response:
    db.session.commit()
    db_path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
    if not os.path.exists(db_path):
        flash("Database file not found", "danger")
        return redirect(url_for("dashboard"))
    audit("backup_generated", "Database backup downloaded", g.user)
    return send_file(db_path, as_attachment=True, download_name="students_backup.sqlite")


# ---------------------------------------------------------------------------
# Token based API
# ---------------------------------------------------------------------------


def _generate_jwt(user: User) -> str:
    payload = {
        "sub": user.id,
        "username": user.username,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }
    token = jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")
    return token if isinstance(token, str) else token.decode("utf-8")


@app.route("/api/token", methods=["POST"])
@login_required
def generate_token():
    form = APIAuthForm()
    if not form.validate_on_submit():
        flash("Invalid request", "danger")
        return redirect(url_for("dashboard"))
    token = _generate_jwt(g.user)
    audit("api_token_generated", "JWT token generated", g.user)
    flash("API token generated. Copy it securely from the activity log.", "info")
    logger.info("Generated JWT for %s: %s", g.user.username, token)
    return redirect(url_for("dashboard"))


def _verify_jwt(token: str) -> Optional[User]:
    try:
        payload = jwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    return User.query.get(payload.get("sub"))


@app.route("/api/students", methods=["GET"])
def api_students():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    token = auth_header.split(" ", 1)[1]
    user = _verify_jwt(token)
    if not user:
        return jsonify({"error": "Invalid token"}), 401
    students = [student.data for student in Student.query.all()]
    audit("api_students_requested", "Students data accessed via API", user)
    return jsonify(students)


# ---------------------------------------------------------------------------
# Audit hooks
# ---------------------------------------------------------------------------


@event.listens_for(sqlite3.Connection, "connect")
def enforce_foreign_keys(dbapi_connection, connection_record):  # pragma: no cover
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


# ---------------------------------------------------------------------------
# CLI utilities
# ---------------------------------------------------------------------------


@app.cli.command("create-admin")
def create_admin():
    """Create an initial admin user if none exists."""

    if User.query.filter_by(role="admin").first():
        print("Admin already exists")
        return
    username = input("Admin username: ")
    email = input("Admin email: ")
    password = input("Admin password: ")
    biometric = input("Biometric phrase (optional): ")
    user = User(username=sanitize_text(username), email=sanitize_text(email), role="admin")
    user.set_password(password)
    if biometric:
        user.set_biometric(biometric)
    db.session.add(user)
    db.session.commit()
    print("Admin created with OTP secret:", user.otp_secret)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------


@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", message="Forbidden"), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", message="Not Found"), 404


@app.errorhandler(500)
def server_error(_):
    db.session.rollback()
    return render_template("error.html", message="An internal error occurred"), 500


# ---------------------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------------------


def initialize_database() -> None:
    db.create_all()
    if not User.query.filter_by(role="admin").first():
        default_admin = User(
            username="admin",
            email="admin@example.com",
            role="admin",
            otp_secret=pyotp.random_base32(),
        )
        default_admin.set_password("ChangeMe123!")
        default_admin.set_biometric("default-biometric")
        db.session.add(default_admin)
        db.session.commit()
        logger.info("Default admin user created: admin / ChangeMe123!")


if __name__ == "__main__":
    initialize_database()
    app.run(debug=True, host="0.0.0.0", port=5000)
