from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import random
from datetime import timedelta, datetime
import re
import os
import uuid
import cloudinary
import cloudinary.uploader
import cloudinary.api

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
    return render_template(
        "event_page.html",
        event=event,
        organizer=organizer
    )
    
@app.route("/join/<int:event_id>")
@login_required
def join(event_id):
    event = Event.query.get_or_404(event_id)
    organizer = User.query.get(event.organizer_id)
    return render_template(
        "join.html",
        event=event,
        organizer=organizer
    )


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

    categories = ["Music Show", "Comedy Show", "Workshop", "Sports", "Play", "Conference", "Adventure", "Performance", "Other"]
    event = None
    
    if event_id:
        event = Event.query.get_or_404(event_id)
        if event.organizer_id != current_user.user_id:
            flash("Access denied. You cannot edit this event.")
            return redirect(url_for('organizer_home'))

    if request.method == 'POST':
        try:
            # Basic event info
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            location = request.form.get('location', '').strip()
            category = request.form.get('category', '')
            
            # Validate required fields
            if not title or not location or not category:
                flash("Please fill all required fields.")
                return render_template('create_event.html', event=event, categories=categories)
            
            # Parse datetime fields
            start_datetime_str = request.form.get('start_datetime', '')
            end_datetime_str = request.form.get('end_datetime', '')
            
            if not start_datetime_str or not end_datetime_str:
                flash("Please provide both start and end date/time.")
                return render_template('create_event.html', event=event, categories=categories)
                
            start_dt = datetime.strptime(start_datetime_str, '%Y-%m-%dT%H:%M')
            end_dt = datetime.strptime(end_datetime_str, '%Y-%m-%dT%H:%M')
            
            # Validate datetime logic
            if end_dt <= start_dt:
                flash("End time must be after start time.")
                return render_template('create_event.html', event=event, categories=categories)
            
            # Registration period (optional)
            reg_start = None
            reg_end = None
            if request.form.get('registration_start'):
                reg_start = datetime.strptime(request.form['registration_start'], '%Y-%m-%dT%H:%M')
            if request.form.get('registration_end'):
                reg_end = datetime.strptime(request.form['registration_end'], '%Y-%m-%dT%H:%M')
                
            # Validate registration period
            if reg_start and reg_end:
                if reg_end <= reg_start:
                    flash("Registration end time must be after registration start time.")
                    return render_template('create_event.html', event=event, categories=categories)
                if reg_end > start_dt:
                    flash("Registration must end before the event starts.")
                    return render_template('create_event.html', event=event, categories=categories)
            
            # Max attendees (optional)
            max_attendees = None
            if request.form.get('max_attendees'):
                try:
                    max_attendees = int(request.form['max_attendees'])
                    if max_attendees <= 0:
                        flash("Maximum attendees must be a positive number.")
                        return render_template('create_event.html', event=event, categories=categories)
                except ValueError:
                    flash("Invalid maximum attendees value.")
                    return render_template('create_event.html', event=event, categories=categories)
                
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
                        return render_template('create_event.html', event=event, categories=categories)

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
                    return render_template('create_event.html', event=event, categories=categories)
                
                for i, ticket_type in enumerate(ticket_types):
                    if ticket_type and ticket_prices[i] and ticket_quantities[i]:
                        try:
                            price = float(ticket_prices[i])
                            quantity = int(ticket_quantities[i])
                            
                            if price < 0:
                                flash("Ticket price cannot be negative.")
                                return render_template('create_event.html', event=event, categories=categories)
                            if quantity <= 0:
                                flash("Ticket quantity must be positive.")
                                return render_template('create_event.html', event=event, categories=categories)
                                
                            new_ticket = Ticket(
                                event_id=event.event_id,
                                type=ticket_type,
                                price=price,
                                max_quantity=quantity
                            )
                            db.session.add(new_ticket)
                        except (ValueError, TypeError):
                            flash(f"Invalid ticket data for {ticket_type}.")
                            return render_template('create_event.html', event=event, categories=categories)
                            
            db.session.commit()
            flash(f"Event '{title}' saved successfully!")
            return redirect(url_for('organizer_home'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}")
            return render_template('create_event.html', event=event, categories=categories)

    return render_template('create_event.html', event=event, categories=categories)

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
    app.run(debug=True)