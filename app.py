# IMPORTS
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

# Image upload config
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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
    
    image_path = db.Column(db.String(200), nullable=True)
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
            if user.role == "organizer":
                return redirect(url_for('organizer_home'))
            else:
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

@app.route('/organizer_home')
@login_required
def organizer_home():
    if current_user.role != "organizer":
        flash("Access denied!")
        return redirect(url_for('dashboard'))

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
        return redirect(url_for('dashboard'))

    categories = ["Music Show", "Comedy Show", "Workshop", "Sports", "Play", "Conference", "Adventure", "Performance", "Other"]
    event = None
    
    if event_id:
        event = Event.query.get_or_404(event_id)
        if event.organizer_id != current_user.user_id:
            flash("Access denied. You cannot edit this event.")
            return redirect(url_for('organizer_home'))

    if request.method == 'POST':
        # Basic event info
        title = request.form['title']
        description = request.form['description']
        start_dt = datetime.strptime(request.form['start_datetime'], '%Y-%m-%dT%H:%M')
        end_dt = datetime.strptime(request.form['end_datetime'], '%Y-%m-%dT%H:%M')
        location = request.form['location']
        category = request.form['category']
        
        # Registration period
        reg_start = None
        reg_end = None
        if request.form.get('registration_start'):
            reg_start = datetime.strptime(request.form['registration_start'], '%Y-%m-%dT%H:%M')
        if request.form.get('registration_end'):
            reg_end = datetime.strptime(request.form['registration_end'], '%Y-%m-%dT%H:%M')
        
        # Max attendees
        max_attendees = None
        if request.form.get('max_attendees'):
            max_attendees = int(request.form['max_attendees'])
            
        # Status
        status = "published" if 'publish' in request.form else "draft"

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
                max_attendees=max_attendees
            )
            db.session.add(event)

        db.session.commit()
        
        # Handle ticket types (from your UI design)
        ticket_types = request.form.getlist('ticket_type[]')
        ticket_prices = request.form.getlist('ticket_price[]')
        ticket_quantities = request.form.getlist('ticket_quantity[]')
        
        if not event_id:  # Only add tickets for new events
            for i, ticket_type in enumerate(ticket_types):
                if ticket_type and ticket_prices[i] and ticket_quantities[i]:
                    new_ticket = Ticket(
                        event_id=event.event_id,
                        type=ticket_type,
                        price=float(ticket_prices[i]),
                        max_quantity=int(ticket_quantities[i])
                    )
                    db.session.add(new_ticket)
        
        db.session.commit()
        flash(f"Event '{title}' saved successfully!")
        return redirect(url_for('organizer_home'))

    return render_template('create_event.html', event=event, categories=categories)

@app.route('/manage_tickets/<int:event_id>', methods=['GET', 'POST'])
@login_required
def manage_tickets(event_id):
    if current_user.role != "organizer":
        flash("Access denied!")
        return redirect(url_for('dashboard'))
    
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

@app.route('/event_analytics/<int:event_id>')
@login_required
def event_analytics(event_id):
    if current_user.role != "organizer":
        flash("Access denied!")
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    if event.organizer_id != current_user.user_id:
        flash("Access denied!")
        return redirect(url_for('organizer_home'))
    
    # Calculate analytics
    total_bookings = event.get_total_bookings()
    total_revenue = event.get_total_revenue()
    ticket_stats = event.get_ticket_stats()
    
    # Attendee analytics
    total_attendees = sum([sum([bt.quantity for bt in booking.tickets]) for booking in event.bookings])
    checked_in = sum([sum([bt.quantity for bt in booking.tickets if bt.check_in_status == 'attended']) for booking in event.bookings])
    
    return render_template('event_analytics.html', 
                         event=event, 
                         total_bookings=total_bookings,
                         total_revenue=total_revenue,
                         total_attendees=total_attendees,
                         checked_in=checked_in,
                         ticket_stats=ticket_stats)
    
    
@app.route('/upload_image/<int:event_id>', methods=['POST'])
@login_required
def upload_image(event_id):
    if current_user.role != "organizer":
        return jsonify({'error': 'Access denied'}), 403
    
    event = Event.query.get_or_404(event_id)
    if event.organizer_id != current_user.user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    if 'image' not in request.files:
        return jsonify({'error': 'No image provided'}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        # Generate unique filename
        filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        event.image_path = f"uploads/{filename}"
        db.session.commit()
        
        return jsonify({'success': True, 'image_path': event.image_path})
    
    return jsonify({'error': 'Invalid file type'}), 400

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/duplicate_event/<int:event_id>')
@login_required
def duplicate_event(event_id):
    if current_user.role != "organizer":
        flash("Access denied!")
        return redirect(url_for('dashboard'))
    
    original_event = Event.query.get_or_404(event_id)
    if original_event.organizer_id != current_user.user_id:
        flash("Access denied!")
        return redirect(url_for('organizer_home'))
    
    # Create duplicate event
    new_event = Event(
        organizer_id=current_user.user_id,
        title=f"Copy of {original_event.title}",
        description=original_event.description,
        category=original_event.category,
        start_datetime=original_event.start_datetime,
        end_datetime=original_event.end_datetime,
        location=original_event.location,
        status="draft",
        registration_start=original_event.registration_start,
        registration_end=original_event.registration_end,
        max_attendees=original_event.max_attendees
    )
    db.session.add(new_event)
    db.session.flush()  # Get the new event ID
    
    # Duplicate tickets
    for ticket in original_event.tickets:
        new_ticket = Ticket(
            event_id=new_event.event_id,
            type=ticket.type,
            price=ticket.price,
            max_quantity=ticket.max_quantity
        )
        db.session.add(new_ticket)
    
    db.session.commit()
    flash(f"Event '{original_event.title}' duplicated successfully!")
    return redirect(url_for('create_event', event_id=new_event.event_id))

@app.route('/delete_event/<int:event_id>')
@login_required
def delete_event(event_id):
    if current_user.role != "organizer":
        flash("Access denied!")
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    if event.organizer_id != current_user.user_id:
        flash("Access denied!")
        return redirect(url_for('organizer_home'))
    
    # Check if event has bookings
    if event.bookings:
        flash("Cannot delete event with existing bookings!")
        return redirect(url_for('organizer_home'))
    
    # Delete associated tickets first
    for ticket in event.tickets:
        db.session.delete(ticket)
    
    # Delete event image if exists
    if event.image_path:
        try:
            os.remove(os.path.join('static', event.image_path))
        except:
            pass
    
    db.session.delete(event)
    db.session.commit()
    flash("Event deleted successfully!")
    return redirect(url_for('organizer_home'))

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
