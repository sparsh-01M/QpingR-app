# app.py - Flask application for vehicle document verification and QR code generator

import os
import uuid
import datetime
import random
import string
import qrcode
import json
import pyotp
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
import base64
import re
from itsdangerous import URLSafeTimedSerializer
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_for_development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf'}

# Ensure uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# Twilio configuration
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER')
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN else None

# Initialize serializer for tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    email_verified = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    phone_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    vehicles = db.relationship('Vehicle', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vehicle_type = db.Column(db.String(50), nullable=False)
    license_plate = db.Column(db.String(20), unique=True, nullable=False)
    make = db.Column(db.String(50))
    model = db.Column(db.String(50))
    year = db.Column(db.Integer)
    document_path = db.Column(db.String(200))
    document_verified = db.Column(db.Boolean, default=False)
    qr_code_path = db.Column(db.String(200))
    unique_code = db.Column(db.String(64), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    contacts = db.relationship('ContactLog', backref='vehicle', lazy=True)

class ContactLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    contact_type = db.Column(db.String(10), nullable=False)  # 'call' or 'message'
    contact_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status = db.Column(db.String(20))  # 'success', 'failed', etc.
    contact_ip = db.Column(db.String(50))
    message_content = db.Column(db.Text, nullable=True)

class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(10), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'email' or 'phone'
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

def send_email_verification(user, code):
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = user.email
        msg['Subject'] = "Verify your email for Vehicle QR"
        
        body = f"""
        Hello,
        
        Thank you for registering with Vehicle QR. Your verification code is: {code}
        
        This code will expire in 30 minutes.
        
        Best regards,
        Vehicle QR Team
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], 587)
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email sending error: {e}")
        return False

def send_phone_verification(user, code):
    if not twilio_client:
        print("Twilio client not initialized")
        return False
    
    try:
        message = twilio_client.messages.create(
            body=f"Your Vehicle QR verification code is: {code}",
            from_=TWILIO_PHONE_NUMBER,
            to=user.phone_number
        )
        return True
    except Exception as e:
        print(f"SMS sending error: {e}")
        return False

def generate_unique_vehicle_code():
    return uuid.uuid4().hex

def generate_qr_code(vehicle):
    # Create contact endpoint URL
    contact_url = f"{request.host_url}contact/{vehicle.unique_code}"
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(contact_url)
    qr.make(fit=True)
    
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    # Add license plate text below QR code
    canvas = Image.new('RGB', (qr_img.pixel_size, qr_img.pixel_size + 40), 'white')
    canvas.paste(qr_img, (0, 0))
    
    draw = ImageDraw.Draw(canvas)
    try:
        font = ImageFont.truetype("arial.ttf", 24)
    except IOError:
        font = ImageFont.load_default()
        
    plate_text = f"Vehicle: {vehicle.license_plate}"
    text_w, text_h = draw.textsize(plate_text, font)
    draw.text(((qr_img.pixel_size - text_w) // 2, qr_img.pixel_size + 10), plate_text, fill="black", font=font)
    
    # Save QR code image
    filename = f"qr_{vehicle.unique_code}.png"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    canvas.save(filepath)
    
    return filename

def check_daily_contact_limit(vehicle_id):
    today = datetime.datetime.utcnow().date()
    today_start = datetime.datetime.combine(today, datetime.time.min)
    today_end = datetime.datetime.combine(today, datetime.time.max)
    
    call_count = ContactLog.query.filter(
        ContactLog.vehicle_id == vehicle_id,
        ContactLog.contact_type == 'call',
        ContactLog.contact_date.between(today_start, today_end)
    ).count()
    
    return call_count < 3  # Allow if less than 3 calls today

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Form validation
        if not all([email, password, confirm_password]):
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        # Create user
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Generate and save verification code
        code = generate_verification_code()
        expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        verification = VerificationCode(user_id=user.id, code=code, type='email', expires_at=expiry)
        db.session.add(verification)
        db.session.commit()
        
        # Send verification email
        if send_email_verification(user, code):
            flash('Registration successful! Please verify your email.', 'success')
            return redirect(url_for('verify_email'))
        else:
            flash('Registration successful, but email sending failed. Please contact support.', 'warning')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if current_user.is_authenticated and current_user.email_verified:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        email = request.form.get('email')
        
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email not found', 'danger')
            return redirect(url_for('verify_email'))
        
        verification = VerificationCode.query.filter_by(
            user_id=user.id, 
            code=code, 
            type='email'
        ).order_by(VerificationCode.created_at.desc()).first()
        
        if not verification or verification.expires_at < datetime.datetime.utcnow():
            flash('Invalid or expired verification code', 'danger')
            return redirect(url_for('verify_email'))
        
        user.email_verified = True
        db.session.delete(verification)
        db.session.commit()
        
        login_user(user)
        flash('Email verified successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('verify_email.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('dashboard')
            return redirect(next_page)
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.email_verified:
        flash('Please verify your email first', 'warning')
        return redirect(url_for('verify_email'))
        
    vehicles = Vehicle.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', vehicles=vehicles)

@app.route('/verify-phone', methods=['GET', 'POST'])
@login_required
def verify_phone():
    if request.method == 'POST':
        if 'send_code' in request.form:
            phone_number = request.form.get('phone_number')
            
            # Validate phone number
            if not re.match(r'^\+?[1-9]\d{1,14}$', phone_number):
                flash('Invalid phone number format. Please use international format: +1234567890', 'danger')
                return redirect(url_for('verify_phone'))
            
            # Check if phone is already in use
            if User.query.filter_by(phone_number=phone_number).first() and current_user.phone_number != phone_number:
                flash('This phone number is already registered', 'danger')
                return redirect(url_for('verify_phone'))
            
            # Save phone number
            current_user.phone_number = phone_number
            db.session.commit()
            
            # Generate and save verification code
            code = generate_verification_code()
            expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
            verification = VerificationCode(user_id=current_user.id, code=code, type='phone', expires_at=expiry)
            db.session.add(verification)
            db.session.commit()
            
            # Send verification SMS
            if send_phone_verification(current_user, code):
                flash('Verification code sent to your phone', 'success')
            else:
                flash('Failed to send verification code. Please try again later.', 'danger')
                
        elif 'verify_code' in request.form:
            code = request.form.get('code')
            
            verification = VerificationCode.query.filter_by(
                user_id=current_user.id, 
                code=code, 
                type='phone'
            ).order_by(VerificationCode.created_at.desc()).first()
            
            if not verification or verification.expires_at < datetime.datetime.utcnow():
                flash('Invalid or expired verification code', 'danger')
                return redirect(url_for('verify_phone'))
            
            current_user.phone_verified = True
            db.session.delete(verification)
            db.session.commit()
            
            flash('Phone number verified successfully!', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('verify_phone.html')

@app.route('/add-vehicle', methods=['GET', 'POST'])
@login_required
def add_vehicle():
    if not current_user.email_verified or not current_user.phone_verified:
        flash('Please verify your email and phone number first', 'warning')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        vehicle_type = request.form.get('vehicle_type')
        license_plate = request.form.get('license_plate')
        make = request.form.get('make')
        model = request.form.get('model')
        year = request.form.get('year')
        
        # Check if a vehicle with this license plate already exists
        if Vehicle.query.filter_by(license_plate=license_plate).first():
            flash('A vehicle with this license plate is already registered', 'danger')
            return redirect(url_for('add_vehicle'))
        
        # Handle document upload
        document = request.files.get('document')
        document_path = None
        
        if document and allowed_file(document.filename):
            filename = secure_filename(f"{uuid.uuid4().hex}_{document.filename}")
            document_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            document.save(document_path)
        else:
            flash('Please upload a valid document (PDF, PNG, JPG, JPEG)', 'danger')
            return redirect(url_for('add_vehicle'))
        
        # Create vehicle record
        unique_code = generate_unique_vehicle_code()
        vehicle = Vehicle(
            user_id=current_user.id,
            vehicle_type=vehicle_type,
            license_plate=license_plate,
            make=make,
            model=model,
            year=year if year else None,
            document_path=filename,
            unique_code=unique_code
        )
        
        db.session.add(vehicle)
        db.session.commit()
        
        # Generate QR code after vehicle is saved and has an ID
        qr_code_path = generate_qr_code(vehicle)
        vehicle.qr_code_path = qr_code_path
        db.session.commit()
        
        flash('Vehicle added successfully! Your document will be verified soon.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_vehicle.html')

@app.route('/vehicle/<int:vehicle_id>')
@login_required
def vehicle_details(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    
    # Ensure user owns this vehicle
    if vehicle.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get recent contact logs
    contacts = ContactLog.query.filter_by(vehicle_id=vehicle.id).order_by(ContactLog.contact_date.desc()).limit(10).all()
    
    return render_template('vehicle_details.html', vehicle=vehicle, contacts=contacts)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    # Security check to prevent unauthorized access
    vehicle = Vehicle.query.filter_by(document_path=filename).first()
    qr_vehicle = Vehicle.query.filter_by(qr_code_path=filename).first()
    
    if vehicle and vehicle.user_id == current_user.id:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    elif qr_vehicle and qr_vehicle.user_id == current_user.id:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    else:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/contact/<unique_code>', methods=['GET'])
def contact_form(unique_code):
    vehicle = Vehicle.query.filter_by(unique_code=unique_code).first()
    
    if not vehicle:
        return render_template('error.html', message="QR code not recognized. Please check and try again.")
    
    return render_template('contact.html', vehicle=vehicle)

@app.route('/api/contact/<unique_code>', methods=['POST'])
def contact_api(unique_code):
    vehicle = Vehicle.query.filter_by(unique_code=unique_code).first()
    
    if not vehicle:
        return jsonify({'success': False, 'message': 'Vehicle not found'})
    
    contact_type = request.json.get('type')  # 'call' or 'message'
    message = request.json.get('message')
    
    if contact_type not in ['call', 'message']:
        return jsonify({'success': False, 'message': 'Invalid contact type'})
    
    # Check daily call limit for calls only
    if contact_type == 'call' and not check_daily_contact_limit(vehicle.id):
        return jsonify({'success': False, 'message': 'Daily call limit reached for this vehicle'})
    
    # Log the contact attempt
    log = ContactLog(
        vehicle_id=vehicle.id,
        contact_type=contact_type,
        contact_ip=request.remote_addr,
        message_content=message if contact_type == 'message' else None
    )
    db.session.add(log)
    db.session.commit()
    
    # Get vehicle owner
    owner = User.query.get(vehicle.user_id)
    
    # Handle contact based on type
    if contact_type == 'call':
        # In a real implementation, this would initiate a masked call via Twilio/similar service
        # For demo purposes, we'll just simulate a successful call
        log.status = 'simulated'
        db.session.commit()
        return jsonify({'success': True, 'message': 'Call initiated', 'call_token': 'DEMO_TOKEN'})
    
    elif contact_type == 'message':
        if not message:
            log.status = 'failed'
            db.session.commit()
            return jsonify({'success': False, 'message': 'Message content is required'})
            
        # In real implementation, send SMS via Twilio or similar
        try:
            if twilio_client:
                twilio_message = twilio_client.messages.create(
                    body=f"Vehicle {vehicle.license_plate}: {message}",
                    from_=TWILIO_PHONE_NUMBER,
                    to=owner.phone_number
                )
                log.status = 'sent'
            else:
                log.status = 'simulated'
            
            db.session.commit()
            return jsonify({'success': True, 'message': 'Message sent successfully'})
        except Exception as e:
            log.status = 'failed'
            db.session.commit()
            return jsonify({'success': False, 'message': 'Failed to send message'})

@app.route('/admin/verify-documents')
@login_required
def admin_verify_documents():
    # In a real application, this would be protected by admin role check
    # For demo, we'll allow any logged in user to access this page
    
    unverified_vehicles = Vehicle.query.filter_by(document_verified=False).all()
    return render_template('admin_verify.html', vehicles=unverified_vehicles)

@app.route('/admin/verify/<int:vehicle_id>', methods=['POST'])
@login_required
def admin_verify_vehicle(vehicle_id):
    # In a real application, this would be protected by admin role check
    
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    vehicle.document_verified = True
    db.session.commit()
    
    flash('Vehicle document verified successfully', 'success')
    return redirect(url_for('admin_verify_documents'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
