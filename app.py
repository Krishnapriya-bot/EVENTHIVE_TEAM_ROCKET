# IMPORTS
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re

# APP CONFIG
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eventhive.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "supersecretkey"  # change this in production!

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"  # if not logged in, redirect here

# HELPERS

def validate_password(password):
    """
    Returns True if password meets security conditions, else False.
    Conditions:
    - At least 8 characters
    - 1 lowercase
    - 1 uppercase
    - 1 digit
    - 1 special character
    """
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


# MODELS

class User(UserMixin, db.Model):   # UserMixin integrates with Flask-Login
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=False)  # 'organizer' or 'attendee'
    password_hash = db.Column(db.String(200), nullable=False)

    events = db.relationship("Event", backref="organizer", lazy=True)
    bookings = db.relationship("Booking", backref="user", lazy=True)

    # Flask-Login requires these:
    def get_id(self):
        return str(self.user_id)


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
    status = db.Column(db.String(20), default="draft")  # draft/published
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    tickets = db.relationship("Ticket", backref="event", lazy=True)
    bookings = db.relationship("Booking", backref="event", lazy=True)


class Ticket(db.Model):
    __tablename__ = "tickets"
    ticket_id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("events.event_id"), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # General, VIP, etc.
    price = db.Column(db.Float, nullable=False)
    max_quantity = db.Column(db.Integer, nullable=False)

    booking_tickets = db.relationship("BookingTicket", backref="ticket", lazy=True)


class Booking(db.Model):
    __tablename__ = "bookings"
    booking_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey("events.event_id"), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    payment_status = db.Column(db.String(20), default="pending")  # pending/success/failed
    booking_date = db.Column(db.DateTime, default=datetime.utcnow)

    tickets = db.relationship("BookingTicket", backref="booking", lazy=True)


class BookingTicket(db.Model):
    __tablename__ = "booking_tickets"
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey("bookings.booking_id"), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.ticket_id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    qr_code = db.Column(db.String(200), unique=True, nullable=True)
    check_in_status = db.Column(db.String(20), default="pending")  # pending/checked-in


# ROUTES

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        role = request.form['role']
        password = request.form['password']

        if not validate_password(password):
            flash("Password must be at least 8 chars long, include lowercase, uppercase, number, and special character.")
            return render_template('register.html')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please login.")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(
            name=name,
            email=email,
            phone=phone,
            role=role,
            password_hash=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please login.")
        return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!")
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return f"Hello, {current_user.name}! This is your dashboard."


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('login'))


@app.route('/initdb')
def initdb():
    db.create_all()
    return "Database Initialized!"


if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True)
