from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session, json, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import qrcode
import time
from base64 import b64encode
from io import BytesIO
import socket
import uuid
from flask_weasyprint import HTML, render_pdf
from io import BytesIO
from flask_mail import Message
import random
from datetime import timedelta, datetime
import re
import os
import uuid
import cloudinary
import cloudinary.uploader
import cloudinary.api
from geopy.geocoders import Nominatim

geolocator = Nominatim(user_agent="eventhive_app")

CACHE_FILE = 'locations_cache.json'
locations_cache = {}

try:
    with open(CACHE_FILE, 'r') as f:
        locations_cache = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    locations_cache = {}

# APP CONFIG
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eventhive.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_temporary_and_insecure_key') # Use an environment variable

# Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_DEFAULT_SENDER'] = 'testingrpp09@gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'testingrpp09@gmail.com') # Use environment variable
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'bwvk fyuq ifuc anuq') # Use environment variable

# Image upload config
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

cloudinary.config(
  cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME', "dvkjxdsbs"),
  api_key = os.environ.get('CLOUDINARY_API_KEY', "879149672215546"),
  api_secret = os.environ.get('CLOUDINARY_API_SECRET', "fDuTemSJCPMZ7iHERq0z6D-vbyw")
)

db = SQLAlchemy(app)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

def get_local_ip():
    """Get the local IP address of the machine"""
    ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return ip

LOCAL_IP = get_local_ip()
BASE_URL = f"http://{LOCAL_IP}:5000"

class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=False) 
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

    tickets = db.relationship("Ticket", backref="event", lazy=True, cascade="all, delete-orphan")
    bookings = db.relationship("Booking", backref="event", lazy=True)
    
    image_url = db.Column(db.String(500), nullable=True)  # Cloudinary URL
    registration_start = db.Column(db.DateTime, nullable=True)
    registration_end = db.Column(db.DateTime, nullable=True)
    max_attendees = db.Column(db.Integer, nullable=True)
    
    def get_total_bookings(self):
        return len(self.bookings)
    
    def get_total_revenue(self):
        return sum([booking.total_amount for booking in self.bookings if booking.payment_status == 'completed'])
    
    def get_ticket_stats(self):
        stats = {}
        for ticket in self.tickets:
            booked = sum([bt.quantity for booking in self.bookings 
                         for bt in booking.tickets if bt.ticket_id == ticket.ticket_id])
            stats[ticket.type] = {
                'total': ticket.max_quantity,
                'sold': booked,
                'remaining': ticket.max_quantity - booked,
                'revenue': booked * ticket.price
            }
        return stats

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

# yeh saare woh functions hai jo baar baar use karne padte hai and mai predefine krna chahti hu

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
    try:
        msg = Message("Your OTP Code", recipients=[user.email])
        msg.body = f"Hello {user.name},\n\nA very warm welcome from Team EventHive!\nYour OTP is {otp}. It will expire in 5 minutes.\n\n-Team EventHive"
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
# yaha se page routes start hote hai

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
        
        if send_otp_email(new_user, otp_code):
            session['pending_user'] = new_user.user_id
            flash("Registration successful! Verify OTP sent to your email.")
            return redirect(url_for('verify_otp'))
        else:
            flash("Registration successful, but failed to send OTP email. Please try again.")
            return render_template('register.html')

    return render_template('register.html')

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

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    pending_user_id = session.get('pending_user')
    if not pending_user_id:
        flash("No pending verification found.", "danger")
        return redirect(url_for('register'))

    user = User.query.get(pending_user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('register'))

    # Delete any existing OTPs for the user to ensure a clean slate
    OTP.query.filter_by(user_id=user.user_id).delete()
    
    otp_code = generate_otp()
    otp_entry = OTP(user_id=user.user_id, code=otp_code, expiry=datetime.utcnow() + timedelta(minutes=5))
    db.session.add(otp_entry)

    if send_otp_email(user, otp_code):
        db.session.commit()
        flash("A new OTP has been sent to your email.", "info")
    else:
        db.session.rollback()
        flash("Failed to send a new OTP. Please try again later.", "danger")

    return redirect(url_for('verify_otp'))

@app.route('/toggle_event_status/<int:event_id>')
@login_required
def toggle_event_status(event_id):
    event = Event.query.get_or_404(event_id)
    if event.organizer_id != current_user.user_id:
        flash("Access denied!")
        return redirect(url_for('organizer_home'))
    event.status = "draft" if event.status == "published" else "published"
    db.session.commit()
    flash(f"Event '{event.title}' status updated to {event.status}.")
    return redirect(url_for('organizer_home'))

# -------- LOGIN --------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user:
            # Check the password
            if check_password_hash(user.password_hash, password):
                # Check if the user is verified
                if not user.verified:
                    session['pending_user'] = user.user_id
                    flash("Please verify your email with OTP before logging in.")
                    return redirect(url_for('verify_otp'))
                
                # All checks pass, log the user in using Flask-Login
                login_user(user)
                flash("Login successful!")
                
                if user.role == "organizer":
                    return redirect(url_for('organizer_home'))
                else:
                    return redirect(url_for('eventhive'))
            else:
                flash("Invalid credentials!")
                return redirect(url_for('login'))
        else:
            flash("Invalid credentials!")
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/eventhive')
@login_required
def eventhive():
    events = Event.query.filter_by(status="published")\
        .order_by(Event.start_datetime.desc())\
        .limit(5).all()

    categories = db.session.query(Event.category).distinct().all()
    categories = [cat[0] for cat in categories]

    return render_template( 
    'eventhive.html',
    name=current_user.name,
    events=events,
    categories=categories)

@app.route("/event/<int:event_id>")
@login_required
def event_page(event_id):
    event = Event.query.get_or_404(event_id)
    organizer = User.query.get(event.organizer_id)
    geolocator = Nominatim(user_agent="eventhive_app")
    location = geolocator.geocode(event.location)
    lat, lon = None, None
    if location:
        lat, lon = location.latitude, location.longitude
    return render_template(
        "event_page.html",
        event=event,
        organizer=organizer,
        lat=lat,
        lon=lon,
        name=current_user.name
    )
    
@app.route("/join/<int:event_id>")
@login_required
def join_event(event_id): # The function name is 'join_event'
    # This route will now redirect to the new booking page
    return redirect(url_for('book_event', event_id=event_id))


@app.route('/organizer_home')
@login_required
def organizer_home():
    if current_user.role != "organizer":
        flash("Access denied!")
        return redirect(url_for('eventhive'))

    # Pagination & filters
    page = request.args.get('page', 1, type=int)
    per_page = 6

    # Filters
    category_filter = request.args.get('category', None)
    status_filter = request.args.get('status', None)
    search_query = request.args.get('search', None)

    query = Event.query.filter_by(organizer_id=current_user.user_id)
    
    if category_filter:
        query = query.filter_by(category=category_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if search_query:
        query = query.filter(Event.title.ilike(f"%{search_query}%"))

    events = query.order_by(Event.start_datetime.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Get categories for filter dropdown
    categories = db.session.query(Event.category).filter_by(
        organizer_id=current_user.user_id
    ).distinct().all()
    categories = [cat[0] for cat in categories]

    return render_template(
        'organizer_home.html',
        events=events,
        name=current_user.name,
        categories=categories,
        category_filter=category_filter,
        status_filter=status_filter,
        search_query=search_query
    )
    
@app.route('/create_event', methods=['GET', 'POST'])
@app.route('/create_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def create_event(event_id=None):
    if current_user.role != "organizer":
        flash("Access denied. Only organizers can create events.")
        return redirect(url_for('eventhive'))
    
    now = datetime.now()

    categories = ["Music Show", "Comedy Show", "Workshop", "Sports", "Play", "Conference", "Adventure", "Performance", "Other"]
    event = None
    location_details = {}  # Initialize an empty dictionary for lat/lon

    if event_id:
        event = Event.query.get_or_404(event_id)
        if event.organizer_id != current_user.user_id:
            flash("Access denied. You cannot edit this event.")
            return redirect(url_for('organizer_home'))
        # Note: Since we are not storing lat/lon, this will not be populated
        # if the event was created after this change.
    
    if request.method == 'POST':
        try:
            # Basic event info
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            location = request.form.get('location', '').strip()
            category = request.form.get('category', '')
            
            # Use geopy to get latitude and longitude
            try:
                location_data = geolocator.geocode(location)
                if location_data:
                    location_details['latitude'] = location_data.latitude
                    location_details['longitude'] = location_data.longitude
                else:
                    flash("Could not find the coordinates for the specified location. Please try a different name.")
                    return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
            except Exception as e:
                flash(f"An error occurred while geocoding the location: {str(e)}")
                return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
            
            # Validate required fields
            if not title or not location or not category:
                flash("Please fill all required fields.")
                return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)

            # Parse datetime fields
            start_datetime_str = request.form.get('start_datetime', '')
            end_datetime_str = request.form.get('end_datetime', '')
            
            if not start_datetime_str or not end_datetime_str:
                flash("Please provide both start and end date/time.")
                return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)

            start_dt = datetime.strptime(start_datetime_str, '%Y-%m-%dT%H:%M')
            end_dt = datetime.strptime(end_datetime_str, '%Y-%m-%dT%H:%M')
            
            # NEW SERVER-SIDE VALIDATION: CHECK IF DATE HAS PASSED
            if start_dt < datetime.now():
                flash("The event's start date cannot be in the past.")
                return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
            
            # Validate datetime logic
            if end_dt <= start_dt:
                flash("End time must be after start time.")
                return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
            
            # Registration period (optional)
            reg_start = None
            reg_end = None
            if request.form.get('registration_start'):
                reg_start = datetime.strptime(request.form['registration_start'], '%Y-%m-%dT%H:%M')
            if request.form.get('registration_end'):
                reg_end = datetime.strptime(request.form['registration_end'], '%Y-%m-%dT%H:%M')

            # NEW SERVER-SIDE VALIDATION: CHECK REGISTRATION DATE
            if reg_start and reg_start < datetime.now():
                flash("The registration start date cannot be in the past.")
                return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
            
            # Validate registration period
            if reg_start and reg_end:
                if reg_end <= reg_start:
                    flash("Registration end time must be after registration start time.")
                    return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
                if reg_end > start_dt:
                    flash("Registration must end before the event starts.")
                    return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
            
            # Max attendees (optional)
            max_attendees = None
            if request.form.get('max_attendees'):
                try:
                    max_attendees = int(request.form['max_attendees'])
                    if max_attendees <= 0:
                        flash("Maximum attendees must be a positive number.")
                        return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
                except ValueError:
                    flash("Invalid maximum attendees value.")
                    return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
                    
            # Status
            status = "published" if 'publish' in request.form else "draft"

            # Handle image upload
            image_url = None
            if 'image' in request.files:
                image_file = request.files['image']
                if image_file and image_file.filename != '':
                    try:
                        # Upload the image to Cloudinary
                        upload_result = cloudinary.uploader.upload(image_file)
                        image_url = upload_result['secure_url']
                    except Exception as e:
                        flash(f"Error uploading image: {e}")
                        return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)

            if event:  # Update existing event
                event.title = title
                event.description = description
                event.start_datetime = start_dt
                event.end_datetime = end_dt
                event.location = location
                event.category = category
                event.status = status
                event.registration_start = reg_start
                event.registration_end = reg_end
                event.max_attendees = max_attendees
                if image_url:
                    event.image_url = image_url
            else:  # Create new event
                event = Event(
                    organizer_id=current_user.user_id,
                    title=title,
                    description=description,
                    start_datetime=start_dt,
                    end_datetime=end_dt,
                    location=location,
                    category=category,
                    status=status,
                    registration_start=reg_start,
                    registration_end=reg_end,
                    max_attendees=max_attendees,
                    image_url=image_url
                )
                db.session.add(event)

            db.session.commit()
            
            # Handle ticket types (only for new events)
            if not event_id:
                ticket_types = request.form.getlist('ticket_type[]')
                ticket_prices = request.form.getlist('ticket_price[]')
                ticket_quantities = request.form.getlist('ticket_quantity[]')
                
                # Validate ticket data
                if len(ticket_types) != len(ticket_prices) or len(ticket_prices) != len(ticket_quantities):
                    flash("Ticket data mismatch. Please check your ticket information.")
                    return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
                
                for i, ticket_type in enumerate(ticket_types):
                    if ticket_type and ticket_prices[i] and ticket_quantities[i]:
                        try:
                            price = float(ticket_prices[i])
                            quantity = int(ticket_quantities[i])
                            
                            if price < 0:
                                flash("Ticket price cannot be negative.")
                                return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
                            if quantity <= 0:
                                flash("Ticket quantity must be positive.")
                                return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
                                
                            new_ticket = Ticket(
                                event_id=event.event_id,
                                type=ticket_type,
                                price=price,
                                max_quantity=quantity
                            )
                            db.session.add(new_ticket)
                        except (ValueError, TypeError):
                            flash(f"Invalid ticket data for {ticket_type}.")
                            return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)
                            
            db.session.commit()
            flash(f"Event '{title}' saved successfully!")
            return redirect(url_for('organizer_home'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}")
            return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)

    return render_template('create_event.html', event=event, categories=categories, location_details=location_details, now=now)

@app.route('/attendees/<int:event_id>')
@login_required
def attendees(event_id):
    event = Event.query.get_or_404(event_id)
    if event.organizer_id != current_user.user_id:
        flash("Access denied!")
        return redirect(url_for('organizer_home'))

    # Filters
    gender_filter = request.args.get('gender', None)
    attended_filter = request.args.get('attended', None)

    query = Booking.query.filter_by(event_id=event_id).join(User)
    if gender_filter:
        query = query.filter(User.role==gender_filter)
    if attended_filter:
        if attended_filter.lower() == "attended":
            query = query.join(BookingTicket).filter(BookingTicket.check_in_status=="attended")
        elif attended_filter.lower() == "not attended":
            query = query.join(BookingTicket).filter(BookingTicket.check_in_status!="attended")

    bookings = query.all()
    return render_template('attendees.html', bookings=bookings, event=event)

@app.route('/get_location_coords', methods=['POST'])
def get_location_coords():
    location_name = request.json.get('location')
    if not location_name:
        return jsonify({'error': 'Location not provided'}), 400

    try:
        location_data = geolocator.geocode(location_name)
        if location_data:
            return jsonify({
                'latitude': location_data.latitude,
                'longitude': location_data.longitude
            })
        else:
            return jsonify({'error': 'Location not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
@app.route('/manage_tickets/<int:event_id>', methods=['GET', 'POST'])
@login_required
def manage_tickets(event_id):
    if current_user.role != "organizer":
        flash("Access denied!")
        return redirect(url_for('eventhive'))
    
    event = Event.query.get_or_404(event_id)
    if event.organizer_id != current_user.user_id:
        flash("Access denied!")
        return redirect(url_for('organizer_home'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_ticket':
            ticket_type = request.form['ticket_type']
            price = float(request.form['price'])
            max_quantity = int(request.form['max_quantity'])
            
            new_ticket = Ticket(
                event_id=event_id,
                type=ticket_type,
                price=price,
                max_quantity=max_quantity
            )
            db.session.add(new_ticket)
            db.session.commit()
            flash(f"Ticket type '{ticket_type}' added successfully!")
        
        elif action == 'update_ticket':
            ticket_id = int(request.form['ticket_id'])
            ticket = Ticket.query.get_or_404(ticket_id)
            if ticket.event_id == event_id:
                ticket.price = float(request.form['price'])
                ticket.max_quantity = int(request.form['max_quantity'])
                db.session.commit()
                flash("Ticket updated successfully!")
        
        elif action == 'delete_ticket':
            ticket_id = int(request.form['ticket_id'])
            ticket = Ticket.query.get_or_404(ticket_id)
            if ticket.event_id == event_id:
                # Check if ticket has bookings
                has_bookings = any(bt.ticket_id == ticket_id for booking in event.bookings for bt in booking.tickets)
                if not has_bookings:
                    db.session.delete(ticket)
                    db.session.commit()
                    flash("Ticket type deleted successfully!")
                else:
                    flash("Cannot delete ticket type with existing bookings!")
    
    tickets = Ticket.query.filter_by(event_id=event_id).all()
    return render_template('manage_tickets.html', event=event, tickets=tickets)

@app.route('/event/<int:event_id>')
def view_event(event_id):
    event = Event.query.get_or_404(event_id)
    return render_template('event_page.html', event=event)

@app.route('/delete_event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    if current_user.role != "organizer":
        flash("Access denied!")
        return redirect(url_for('eventhive'))
        
    event = Event.query.get_or_404(event_id)
    if event.organizer_id != current_user.user_id:
        flash("Access denied. You cannot delete this event.")
        return redirect(url_for('organizer_home'))
    
    try:
        # Delete associated tickets (cascade should handle this, but being explicit)
        for ticket in event.tickets:
            db.session.delete(ticket)
        
        db.session.delete(event)
        db.session.commit()
        flash("Event deleted successfully!")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting event: {str(e)}")
    
    return redirect(url_for('organizer_home'))

@app.route('/book_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def book_event(event_id):
    event = Event.query.get_or_404(event_id)
    tickets = event.tickets
    
    if request.method == 'POST':
        quantities_json = request.form.get('quantities')
        
        if not quantities_json:
            flash("Please select at least one ticket.", "warning")
            return redirect(url_for('book_event', event_id=event.event_id))

        try:
            quantities = json.loads(quantities_json)
        except json.JSONDecodeError:
            flash("Invalid data submitted.", "danger")
            return redirect(url_for('book_event', event_id=event.event_id))

        selected_tickets_details = []
        total_amount = 0

        for ticket_id_str, quantity in quantities.items():
            if int(quantity) > 0:
                ticket = Ticket.query.get(int(ticket_id_str))
                if not ticket or ticket.event_id != event.event_id:
                    flash("Invalid ticket selected.", "danger")
                    return redirect(url_for('book_event', event_id=event.event_id))
                
                # You can add the availability check here as before
                
                total_amount += ticket.price * int(quantity)
                selected_tickets_details.append({
                    'id': ticket.ticket_id,
                    'type': ticket.type,
                    'price': ticket.price,
                    'quantity': int(quantity)
                })
        
        if not selected_tickets_details:
            flash("Please select at least one ticket to proceed.", "warning")
            return redirect(url_for('book_event', event_id=event.event_id))
        
        # Store selected tickets and total amount in the session
        session['selected_tickets'] = selected_tickets_details
        session['total_amount'] = total_amount
        session['event_id'] = event.event_id

        return redirect(url_for('checkout'))

    return render_template('booking_page.html', event=event, tickets=tickets)


# Replace your existing checkout route with this fixed version

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    # Retrieve selected tickets and total amount from the session
    selected_tickets = session.get('selected_tickets')
    total_amount = session.get('total_amount')
    event_id = session.get('event_id')

    if not selected_tickets or not event_id:
        flash("No tickets selected. Please start a new booking.", "danger")
        return redirect(url_for('eventhive'))

    event = Event.query.get_or_404(event_id)

    if request.method == 'POST':
        # Retrieve attendee names from the form
        attendee_names = request.form.getlist('attendee_name[]')
        
        # Check if the number of names matches the total quantity of tickets
        total_quantity = sum(t['quantity'] for t in selected_tickets)
        if len(attendee_names) != total_quantity:
            flash("Please provide a name for each ticket.", "danger")
            return redirect(url_for('checkout'))

        try:
            # Create a single booking entry
            new_booking = Booking(
                user_id=current_user.user_id,
                event_id=event_id,
                total_amount=total_amount,
                payment_status="completed" # Assuming cash on delivery
            )
            db.session.add(new_booking)
            db.session.commit() # Commit to get the booking_id

            # Prepare data for PDF generation and email
            tickets_for_pdf = []
            name_index = 0
            
            # Create a BookingTicket entry for each individual ticket
            for ticket_info in selected_tickets:
                ticket_obj = Ticket.query.get(ticket_info['id'])
                if not ticket_obj:
                    flash("Ticket not found. Please try again.", "danger")
                    db.session.rollback()
                    return redirect(url_for('checkout'))
                
                for _ in range(ticket_info['quantity']):
                    # Generate a unique QR code identifier
                    unique_code = str(uuid.uuid4())
                    
                    # Create the check-in URL for the QR code (ADD THIS LINE)
                    checkin_url = f"{BASE_URL}/check-in/{unique_code}"
                    
                    # Generate QR code image as base64 data URI
                    qr = qrcode.QRCode(
                        version=1,
                        error_correction=qrcode.constants.ERROR_CORRECT_L,
                        box_size=10,
                        border=4,
                    )
                    qr.add_data(checkin_url)  # CHANGE THIS LINE: use checkin_url instead of unique_code
                    qr.make(fit=True)
                    
                    img = qr.make_image(fill_color="black", back_color="white")
                    
                    # Save the image to a BytesIO object
                    img_buffer = BytesIO()
                    img.save(img_buffer, format='PNG')
                    
                    # Encode the image data to base64
                    img_base64 = b64encode(img_buffer.getvalue()).decode('utf-8')
                    qr_data_uri = f"data:image/png;base64,{img_base64}"
                    
                    booking_ticket = BookingTicket(
                        booking_id=new_booking.booking_id,
                        ticket_id=ticket_obj.ticket_id,
                        quantity=1, 
                        qr_code=unique_code
                    )
                    db.session.add(booking_ticket)
                    tickets_for_pdf.append({
                        'type': ticket_obj.type,
                        'price': ticket_obj.price,
                        'qr_code_data': unique_code,
                        'qr_code_image': qr_data_uri,
                        'checkin_url': checkin_url,  # ADD THIS LINE (optional, for reference)
                        'attendee_name': attendee_names[name_index]
                    })
                    name_index += 1
            
            db.session.commit()

            # Notify organizer by email
            try:
                organizer = User.query.get(event.organizer_id)
                msg = Message(
                    subject=f"New Registration for {event.title}",
                    recipients=[organizer.email],
                    body=f"{current_user.name} has joined your event '{event.title}'."
                )
                mail.send(msg)
            except Exception as e:
                print(f"Failed to send organizer notification: {e}")

            # Generate the PDF with tickets
            html_content = render_template(
                'tickets_pdf.html',
                event=event,
                booking=new_booking,
                tickets=tickets_for_pdf
            )
            pdf_data = HTML(string=html_content).write_pdf()

            # Send the email with the PDF attachment
            msg = Message(
                subject=f"Your Tickets for {event.title}",
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[current_user.email]
            )
            msg.body = f"Hello {current_user.name},\n\nThank you for your booking! Please find your tickets attached.\n\nEnjoy the event!"
            msg.attach(f"{event.title}_tickets.pdf", "application/pdf", pdf_data)
            mail.send(msg)

            # Clear the session data and redirect to a confirmation page
            session.pop('selected_tickets', None)
            session.pop('total_amount', None)
            session.pop('event_id', None)
            
            flash("Your booking is complete and tickets have been sent to your email!", "success")
            return redirect(url_for('eventhive'))

        except Exception as e:
            db.session.rollback()
            print(f"Error during checkout: {e}")
            flash(f"An error occurred during booking: {str(e)}", "danger")
            return redirect(url_for('checkout'))

    return render_template('checkout.html', event=event, selected_tickets=selected_tickets, total_amount=total_amount)
    
@app.route('/check-in/<string:qr_code>')
def check_in(qr_code):
    """Enhanced check-in route that returns JSON for API calls and HTML for browser visits"""
    booking_ticket = BookingTicket.query.filter_by(qr_code=qr_code).first()

    if not booking_ticket:
        if request.headers.get('Accept', '').startswith('application/json'):
            return jsonify({"status": "error", "message": "❌ Invalid Ticket"}), 404
        return render_template_string("""
        <h2>❌ Invalid Ticket</h2>
        <p>This QR code is not valid or has expired.</p>
        <a href="{{ url_for('eventhive') }}">Back to Events</a>
        """), 404
    
    # Check if the ticket has already been checked in
    if booking_ticket.check_in_status == 'checked-in':
        if request.headers.get('Accept', '').startswith('application/json'):
            return jsonify({"status": "error", "message": "⚠️ Already Checked-In"}), 400
        return render_template_string("""
        <h2>⚠️ Already Checked-In</h2>
        <p>This ticket has already been used for check-in.</p>
        <p><strong>Event:</strong> {{ ticket.ticket.event.title }}</p>
        <p><strong>Ticket Type:</strong> {{ ticket.ticket.type }}</p>
        <a href="{{ url_for('eventhive') }}">Back to Events</a>
        """, ticket=booking_ticket), 400
    
    # Update the status and commit
    booking_ticket.check_in_status = 'checked-in'
    db.session.commit()
    
    if request.headers.get('Accept', '').startswith('application/json'):
        return jsonify({"status": "success", "message": "✅ Check-In Successful"})
    
    return render_template_string("""
    <h2>✅ Check-In Successful!</h2>
    <p><strong>Event:</strong> {{ ticket.ticket.event.title }}</p>
    <p><strong>Ticket Type:</strong> {{ ticket.ticket.type }}</p>
    <p><strong>Attendee:</strong> {{ booking.user.name }}</p>
    <p><strong>Check-in Time:</strong> {{ now.strftime('%Y-%m-%d %H:%M:%S') }}</p>
    <a href="{{ url_for('eventhive') }}">Back to Events</a>
    """, ticket=booking_ticket, booking=booking_ticket.booking, now=datetime.utcnow())

# Add this new scanner route for event staff
@app.route('/scanner')
@login_required
def scanner():
    """QR Code scanner page for event staff"""
    if current_user.role != "organizer":
        flash("Access denied. Only organizers can access the scanner.")
        return redirect(url_for('eventhive'))
    
    return render_template_string(f"""
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EventHive Check-In Scanner</title>
  <script src="https://unpkg.com/html5-qrcode"></script>
  <style>
    body {{ 
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; 
        padding: 16px; 
        background-color: #f4f4f4;
    }}
    .container {{
        max-width: 400px;
        margin: auto;
        background: white;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }}
    #reader {{ 
        width: 100%; 
        max-width: 320px; 
        margin: 0 auto;
    }}
    #result {{ 
        margin-top: 20px; 
        padding: 15px;
        border-radius: 5px;
        font-size: 16px; 
        text-align: center;
        font-weight: bold;
    }}
    .success {{ background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
    .error {{ background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }}
    .back-btn {{
        display: inline-block;
        margin-top: 20px;
        padding: 10px 20px;
        background-color: #007bff;
        color: white;
        text-decoration: none;
        border-radius: 4px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h2>EventHive Check-In Scanner</h2>
    <p>Scan ticket QR codes to check in attendees</p>
    <div id="reader"></div>
    <div id="result"></div>
    <a href="{{{{ url_for('organizer_home') }}}}" class="back-btn">Back to Dashboard</a>
  </div>
  
  <script>
    let isScanning = true;
    
    function onScanSuccess(decodedText) {{
        if (!isScanning) return;
        
        console.log('QR Code scanned:', decodedText);
        
        // Pause scanning temporarily
        isScanning = false;
        
        // Show processing message
        document.getElementById("result").innerHTML = "Processing...";
        document.getElementById("result").className = "";
        
        // If QR is a full URL, use it; if it's just an ID, construct the URL
        const url = decodedText.startsWith("http") ? decodedText : `{BASE_URL}/check-in/${{decodedText}}`;
        
        fetch(url, {{
            headers: {{
                'Accept': 'application/json'
            }}
        }})
        .then(res => res.json())
        .then(data => {{
            const resultDiv = document.getElementById("result");
            resultDiv.innerText = data.message;
            resultDiv.className = data.status === "success" ? "success" : "error";
            
            // Resume scanning after 3 seconds
            setTimeout(() => {{
                isScanning = true;
                resultDiv.innerHTML = "";
                resultDiv.className = "";
            }}, 3000);
        }})
        .catch(err => {{
            console.error('Error:', err);
            const resultDiv = document.getElementById("result");
            resultDiv.innerText = "Network error or invalid QR code";
            resultDiv.className = "error";
            
            // Resume scanning after 3 seconds
            setTimeout(() => {{
                isScanning = true;
                resultDiv.innerHTML = "";
                resultDiv.className = "";
            }}, 3000);
        }});
    }}
    
    function onScanError(errorMessage) {{
        // Ignore scan errors (they happen frequently while scanning)
    }}
    
    // Initialize the scanner
    new Html5QrcodeScanner("reader", {{ 
        fps: 10, 
        qrbox: 250,
        experimentalFeatures: {{
            useBarCodeDetectorIfSupported: true
        }}
    }}).render(onScanSuccess, onScanError);
  </script>
</body>
</html>
    """)

# Example Flask route
@app.route('/events_map')
@login_required
def events_map():
    locations_cache = {}
    event_markers = []
    cache_updated = False

    # 1. Load the cache at the start of the request
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                locations_cache = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        locations_cache = {}

    try:
        events = Event.query.all()
        for event in events:
            location_name = event.location

            if location_name in locations_cache:
                location_data = locations_cache[location_name]
                # CORRECTED: Use "lat" and "lon" from the JSON file
                location = {'latitude': location_data['lat'], 'longitude': location_data['lon']}
            else:
                print(f"Geocoding new location: {location_name}")
                location_obj = geolocator.geocode(location_name)
                if location_obj:
                    # Store with "lat" and "lon" keys to match the existing format
                    locations_cache[location_name] = {
                        'lat': location_obj.latitude,
                        'lon': location_obj.longitude
                    }
                    cache_updated = True
                    time.sleep(1.1)
                    location = {'latitude': location_obj.latitude, 'longitude': location_obj.longitude}
                else:
                    location = None

            if location:
                event_markers.append({
                    "title": event.title,
                    "lat": location['latitude'],
                    "lon": location['longitude'],
                    "url": url_for('event_page', event_id=event.event_id)
                })

    finally:
        # 2. Save the cache at the end of the request
        if cache_updated:
            with open(CACHE_FILE, 'w') as f:
                json.dump(locations_cache, f)

    return render_template("events_map.html", event_markers=event_markers)

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
    with app.app_context():
        db.create_all() 
    app.run(host="0.0.0.0", port=5000, debug=True)  # Make sure host="0.0.0.0" is there
