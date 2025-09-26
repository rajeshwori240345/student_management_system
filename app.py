from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from cryptography.fernet import Fernet
import pyotp

app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
db = SQLAlchemy(app)

# Encryption key (store securely in production)
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    encrypted_data = db.Column(db.Text, nullable=False)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('otp_verify'))
        else:
            flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/otp-verify', methods=['GET', 'POST'])
def otp_verify():
    if request.method == 'POST':
        otp = request.form['otp']
        user = User.query.filter_by(username=session['username']).first()
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp):
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP", "danger")
    return render_template('otp_verify.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    students = Student.query.all()
    return render_template('dashboard.html', students=students)

@app.route('/add-student', methods=['POST'])
def add_student():
    name = request.form['name']
    encrypted_data = cipher_suite.encrypt(name.encode()).decode()
    student = Student(name=name, encrypted_data=encrypted_data)
    db.session.add(student)
    db.session.commit()
    flash("Student added successfully!", "success")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
