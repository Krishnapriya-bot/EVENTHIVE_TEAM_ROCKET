# IMPORTS
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import random
from datetime import timedelta, datetime
import re

# APP CONFIG
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eventhive.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "supersecretkey"  # change in production!

# Mail config (replace with your SMTP credentials)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_DEFAULT_SENDER'] = 'testingrpp09@gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'testingrpp09@gmail.com'
app.config['MAIL_PASSWORD'] = 'bwvk fyuq ifuc anuq'  

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ------------------------
# HELPERS
# ------------------------
def validate_password(password):
    """Check password complexity rules."""
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(user, otp):
    msg = Message("Your OTP Code", recipients=[user.email])
    msg.body = f"Hello {user.name},\n\nYour OTP is {otp}. It will expire in 5 minutes.\n\n- EventHive Team"
    mail.send(msg)

# ------------------------
# MODELS
# ------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=False)  # 'organizer' or 'attendee'
    password_hash = db.Column(db.String(200), nullable=False)
    verified = db.Column(db.Boolean, default=False)

    events = db.relationship("Event", backref="organizer", lazy=True)
    bookings = db.relationship("Booking", backref="user", lazy=True)

    def get_id(self):
        return str(self.user_id)

class OTP(db.Model):
    __tablename__ = "otps"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Event(db.Model):
    __tablename__ = "events"
    event_id = db.Column(db.Integer, primary_key=True)
    organizer_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False)
    start_datetime = db.Column(db.DateTime, nullable=False)
    end_datetime = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="draft")

    tickets = db.relationship("Ticket", backref="event", lazy=True)
    bookings = db.relationship("Booking", backref="event", lazy=True)

class Ticket(db.Model):
    __tablename__ = "tickets"
    ticket_id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("events.event_id"), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    max_quantity = db.Column(db.Integer, nullable=False)
    booking_tickets = db.relationship("BookingTicket", backref="ticket", lazy=True)

class Booking(db.Model):
    __tablename__ = "bookings"
    booking_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey("events.event_id"), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    payment_status = db.Column(db.String(20), default="pending")
    booking_date = db.Column(db.DateTime, default=datetime.utcnow)
    tickets = db.relationship("BookingTicket", backref="booking", lazy=True)

class BookingTicket(db.Model):
    __tablename__ = "booking_tickets"
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey("bookings.booking_id"), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.ticket_id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    qr_code = db.Column(db.String(200), unique=True, nullable=True)
    check_in_status = db.Column(db.String(20), default="pending")

# ------------------------
# ROUTES
# ------------------------
@app.route('/')
def home():
    return render_template('index.html')

# -------- REGISTER --------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        role = request.form['role']
        password = request.form['password']

        if not validate_password(password):
            flash("Password must be at least 8 chars, include lowercase, uppercase, number, special char.")
            return render_template('register.html')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please login.")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, phone=phone, role=role, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Remove old OTPs and generate new one
        OTP.query.filter_by(user_id=new_user.user_id).delete()
        otp_code = generate_otp()
        otp_entry = OTP(user_id=new_user.user_id, code=otp_code, expiry=datetime.utcnow() + timedelta(minutes=5))
        db.session.add(otp_entry)
        db.session.commit()
        send_otp_email(new_user, otp_code)

        session['pending_user'] = new_user.user_id
        flash("Registration successful! Verify OTP sent to your email.")
        return redirect(url_for('verify_otp'))

    return render_template('register.html')

# -------- VERIFY OTP --------
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    pending_user_id = session.get('pending_user')
    if not pending_user_id:
        flash("No pending verification found. Please register first.", "danger")
        return redirect(url_for('register'))

    user = User.query.get(pending_user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('register'))

    if request.method == 'POST':
        otp_entered = request.form['otp']
        record = OTP.query.filter_by(user_id=user.user_id, code=otp_entered).first()
        if record and record.expiry > datetime.utcnow():
            user.verified = True
            db.session.delete(record)
            db.session.commit()
            session.pop('pending_user', None)
            flash("Email verified successfully! Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid or expired OTP. Please try again.", "danger")

    return render_template('verify_otp.html', email=user.email)

# -------- RESEND OTP --------
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    pending_user_id = session.get('pending_user')
    if not pending_user_id:
        flash("No pending verification found.", "danger")
        return redirect(url_for('register'))

    user = User.query.get(pending_user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('register'))

    OTP.query.filter_by(user_id=user.user_id).delete()
    otp_code = generate_otp()
    otp_entry = OTP(user_id=user.user_id, code=otp_code, expiry=datetime.utcnow() + timedelta(minutes=5))
    db.session.add(otp_entry)
    db.session.commit()
    send_otp_email(user, otp_code)
    flash("A new OTP has been sent to your email.", "info")
    return redirect(url_for('verify_otp'))

# -------- LOGIN --------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            if not user.verified:
                session['pending_user'] = user.user_id
                flash("Please verify your email with OTP before logging in.")
                return redirect(url_for('verify_otp'))
            login_user(user)
            flash("Login successful!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!")
            return redirect(url_for('login'))
    return render_template('login.html')

# -------- DASHBOARD --------
@app.route('/dashboard')
@login_required
def dashboard():
    return f"Hello, {current_user.name}! This is your dashboard."

# -------- LOGOUT --------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('login'))

# -------- INIT DB --------
@app.route('/initdb')
def initdb():
    db.create_all()
    return "Database Initialized!"

# -------- RUN APP --------
if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True)
