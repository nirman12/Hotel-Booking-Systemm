from flask import Flask, render_template, redirect, request, flash, url_for, session, send_file, make_response, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import secrets
from werkzeug.utils import secure_filename
import os
from decimal import Decimal


app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/')
app.secret_key = 'pbkdf2:sha256:600000$dBRwMJV8DnKsSXQP$c6c5c0532d2b8534c26b5acf66a7424772c6f0483772b6c98f2ade0188f9dfc9'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password@localhost/simple_world_hotels'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
secret_key = secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_SECURE=True,    
    SESSION_COOKIE_HTTPONLY=True,  
    SESSION_COOKIE_SAMESITE='Lax' 
)

UPLOAD_FOLDER = 'static/hotel_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='customer')
    phone = db.Column(db.String(15), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    bookings = db.relationship('Booking', backref='user', lazy=True)

    def get_id(self):
        return str(self.user_id)

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def get_booking_history(self):
        return Booking.query.filter_by(user_id=self.user_id).order_by(Booking.booking_date.desc()).all()

    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Hotel(db.Model):
    __tablename__ = 'hotels'

    hotel_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(50), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    about_paragraph = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255))  # New column
    rooms = db.relationship('Room', backref='hotel', cascade='all, delete-orphan')
    bookings = db.relationship('Booking', backref='hotel', cascade='all, delete-orphan')

    def get_available_rooms(self, check_in_date, check_out_date):
        """Get available rooms for the specified dates"""
        unavailable_rooms = Booking.query.filter(
            Booking.hotel_id == self.hotel_id,
            Booking.status == 'confirmed',
            Booking.check_in_date <= check_out_date,
            Booking.check_out_date >= check_in_date
        ).with_entities(Booking.room_id).all()

        unavailable_room_ids = [room[0] for room in unavailable_rooms]
        return Room.query.filter(
            Room.hotel_id == self.hotel_id,
            ~Room.room_id.in_(unavailable_room_ids)
        ).all()

    def get_room_prices(self, check_in_date):
        """Get room prices based on season"""
        is_peak = is_peak_season(check_in_date)
        return [{
            'room_id': room.room_id,
            'type_name': room.type_name,
            'price_per_night': room.peak_rate if is_peak else room.off_peak_rate,
            'max_guests': room.max_guests
        } for room in self.rooms]



class Room(db.Model):
    __tablename__ = 'rooms'
    room_id = db.Column(db.Integer, primary_key=True)
    hotel_id = db.Column(db.Integer, db.ForeignKey('hotels.hotel_id'), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    type_name = db.Column(db.Enum('Standard', 'Double', 'Family'), nullable=False)
    base_rate = db.Column(db.Numeric(10, 2), nullable=False)
    peak_rate = db.Column(db.Numeric(10, 2), nullable=False)
    off_peak_rate = db.Column(db.Numeric(10, 2), nullable=False)
    max_guests = db.Column(db.Integer, nullable=False)

    @property
    def price_per_night(self):
        return float(self.base_rate or 0)

    @property
    def currency_symbol(self):
        return '£'

    def get_current_price(self, check_in_date=None):
        if not check_in_date:
            check_in_date = datetime.now()
        
        month = check_in_date.month
        if 6 <= month <= 8: 
            return float(self.peak_rate)
        elif month in [12, 1, 2]: 
            return float(self.off_peak_rate)
        else: 
            return float(self.base_rate)

class Booking(db.Model):
    __tablename__ = 'bookings'
    booking_id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    hotel_id = db.Column(db.Integer, db.ForeignKey('hotels.hotel_id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.room_id'), nullable=False)
    check_in_date = db.Column(db.Date, nullable=False)
    check_out_date = db.Column(db.Date, nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    booking_date = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    status = db.Column(db.Enum('confirmed', 'cancelled'), default='confirmed')
    number_of_guests = db.Column(db.Integer, nullable=False)

    guest = db.relationship('User', backref='user_bookings')
    booked_hotel = db.relationship('Hotel', backref='hotel_bookings')
    booked_room = db.relationship('Room', backref='room_bookings')

    @property
    def room(self):
        return self.booked_room

    @property
    def user(self):
        return self.guest

    @property
    def hotel(self):
        return self.booked_hotel

    def can_cancel(self):
        """Check if booking can be cancelled (48 hours before check-in)"""
        return datetime.now() <= datetime.combine(self.check_in_date, datetime.min.time()) - timedelta(hours=48)

# Enhanced utility functions
def is_peak_season(date):
    peak_months = [4, 5, 6, 7, 8, 11, 12]
    return date.month in peak_months

def calculate_booking_price(check_in_date, check_out_date, room_id, number_of_guests, booking_date=None):
    room = Room.query.get_or_404(room_id)
    if not booking_date:
        booking_date = datetime.now()

    nights = (check_out_date - check_in_date).days
    if nights <= 0:
        raise ValueError("Check-out date must be after check-in date")

    # Get base price
    base_price = room.get_current_price(check_in_date) * nights

    # Apply advance booking discount
    days_in_advance = (check_in_date - booking_date.date()).days
    discount = get_advance_booking_discount(days_in_advance)
    
    final_price = base_price * (1 - discount)
    
    return {
        'base_price': base_price,
        'discount_percentage': discount * 100,
        'final_price': final_price,
        'nights': nights
    }

def get_advance_booking_discount(days_in_advance):
    if days_in_advance >= 80:
        return 0.30
    elif days_in_advance >= 60:
        return 0.20
    elif days_in_advance >= 45:
        return 0.10
    return 0

def generate_booking_id():
    return 'BOOK' + datetime.now().strftime('%Y%m%d%H%M%S')



def handle_cancellation(booking_id):
    booking = Booking.query.filter_by(booking_id=booking_id).first()
    if booking:
        booking.status = 'cancelled'
        db.session.commit()
        return f"Booking {booking_id} has been cancelled successfully."
    else:
        return f"Booking with ID {booking_id} not found."



@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        city = request.form.get('city')
        return redirect(url_for('hotels', city=city)) 
    return render_template('index.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            user = User.query.filter_by(email=email).first()
            
            if user:
                is_valid = bcrypt.check_password_hash(user.password, password)
                
                if is_valid:
                    login_user(user)
                    session['user_id'] = user.user_id
                    session['email'] = user.email
                    session['role'] = user.role
                    session.permanent = True
                    
                    resp = make_response(redirect(url_for('admin_dashboard' if user.role == 'admin' else 'index')))
                    resp.set_cookie('last_login', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), max_age=30*24*60*60)
                    resp.set_cookie('user_name', f"{user.first_name} {user.last_name}", max_age=30*24*60*60)
                    
                    flash('Login successful!', 'success')
                    return resp
                else:
                    flash('Invalid password. Please try again.', 'error')
            else:
                flash('Email not found. Please register first.', 'error')
        except Exception as e:
            flash('An error occurred during login. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please login instead.', 'error')
            return redirect(url_for('register'))
        
        try:
            # Hash the password using bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Save the user with the hashed password
            new_user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=hashed_password,
                role='customer'
            )
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('last_login')
    resp.delete_cookie('user_name')
    logout_user()
    
    flash("You have been logged out.", "info")
    return resp


@app.route('/hotels', methods=['GET', 'POST'])
def hotels():
    if request.method == 'POST':
        city = request.form.get('city') 
        if city:
            our_hotels = Hotel.query.filter_by(city=city).all()
            other_hotels = Hotel.query.filter(Hotel.city != city).all() 
        else:
            our_hotels = Hotel.query.all()  
            other_hotels = []  
    else:
        
        city = None
        our_hotels = Hotel.query.all()  
        other_hotels = []

    return render_template('hotels.html', city=city or "all cities", our_hotels=our_hotels, other_hotels=other_hotels)

def is_peak_season(date):
    peak_months = [4, 5, 6, 7, 8, 11, 12]  # Peak months: April to August, November, December
    return date.month in peak_months

@app.route('/hotel_details/<int:hotel_id>')
@login_required
def hotel_details(hotel_id):
    hotel = db.session.get(Hotel, hotel_id)
    if not hotel:
        flash('Hotel not found.', 'error')
        return redirect(url_for('index'))

    room_data = Room.query.filter_by(hotel_id=hotel_id).order_by(Room.type_name).all()
    
    if not room_data:
        room_data = [
            Room(hotel_id=hotel_id, city=hotel.city, type_name='Standard', 
                 base_rate=Decimal('0.00'), peak_rate=Decimal('0.00'), 
                 off_peak_rate=Decimal('0.00'), max_guests=1),
            Room(hotel_id=hotel_id, city=hotel.city, type_name='Double', 
                 base_rate=Decimal('0.00'), peak_rate=Decimal('0.00'), 
                 off_peak_rate=Decimal('0.00'), max_guests=2),
            Room(hotel_id=hotel_id, city=hotel.city, type_name='Family', 
                 base_rate=Decimal('0.00'), peak_rate=Decimal('0.00'), 
                 off_peak_rate=Decimal('0.00'), max_guests=4)
        ]
    
    currency = request.args.get('currency', 'GBP')
    
    context = {
        'hotel': hotel,
        'rooms': room_data,
        'current_currency': currency
    }
    
    return render_template('hotel_details.html', **context)

@app.route('/billing/<int:hotel_id>', methods=['GET', 'POST'])
@login_required
def billing(hotel_id):
    try:
        hotel = db.session.get(Hotel, hotel_id)
        if not hotel:
            flash('Hotel not found.', 'error')
            return redirect(url_for('hotels'))

        room_type_map = {
            'StandardRoom': 'Standard',
            '1Adult': 'Double', 
            'FamilyRoom': 'Family'
        }
        
        guest_count_map = {
            '1Guest': 1,
            '2Guests': 2,
            '3Guests': 3,
            '4Guests': 4
        }

        if request.method == 'POST':
            try:
                check_in = datetime.strptime(request.form['checkIn'], '%Y-%m-%d').date()
                check_out = datetime.strptime(request.form['checkOut'], '%Y-%m-%d').date()
                
                room_type = room_type_map.get(request.form['rooms'])
                number_of_guests= int(request.form['numberofPeople'])
                
                print(type(number_of_guests))
                print(number_of_guests)
                
                nights = int(request.form['nights'])

                if not check_in:
                    print("Check-in date is required.", 'error')
                    return redirect(url_for('billing', hotel_id=hotel_id))
                if not check_out:
                    print("Check-out date is required.", 'error')
                    return redirect(url_for('billing', hotel_id=hotel_id))
                if not room_type:
                    print("Room type is required.", 'error')
                    return redirect(url_for('billing', hotel_id=hotel_id))
                if not number_of_guests:
                    print("Number of guests is required.", 'error')
                    return redirect(url_for('billing', hotel_id=hotel_id))

                if check_in < datetime.now().date():
                    print('Check-in date cannot be in the past.', 'error')
                    return redirect(url_for('billing', hotel_id=hotel_id))

                available_rooms = hotel.get_available_rooms(check_in, check_out)
                selected_room = next((r for r in available_rooms if r.type_name == room_type), None)

                if not selected_room:
                    print('Selected room type is not available for these dates.', 'error')
                    return redirect(url_for('billing', hotel_id=hotel_id))

                price_info = calculate_booking_price(
                    check_in, 
                    check_out, 
                    selected_room.room_id, 
                    number_of_guests
                )

                booking = Booking(
                    booking_id=generate_booking_id(),
                    user_id=current_user.user_id,
                    hotel_id=hotel_id,
                    room_id=selected_room.room_id,
                    check_in_date=check_in,
                    check_out_date=check_out,
                    total_price=price_info['final_price'],
                    number_of_guests=number_of_guests, 
                    booking_date=datetime.now(),
                    status='confirmed'
                )

                db.session.add(booking)
                db.session.commit()

                return redirect(url_for('hotel_booked'))

            except ValueError as ve:
                flash(f'Invalid input: {str(ve)}', 'error')
                return redirect(url_for('billing', hotel_id=hotel_id))
            except Exception as e:
                db.session.rollback()
                print(f'Booking error: {str(e)}', 'error')
                return redirect(url_for('hotel_details', hotel_id=hotel_id))

        return render_template('billing.html', 
                            hotel=hotel, 
                            rooms=hotel.get_room_prices(datetime.now().date()))

    except Exception as e:
        flash(f'An unexpected error occurred: {str(e)}', 'error')
        return redirect(url_for('hotels'))


@app.route('/hotel_booked', methods=['GET', 'POST'])
@login_required
def hotel_booked():
    currency = request.args.get('currency', 'USD')
    
    
    latest_booking = db.session.query(Booking).join(
        Room, Booking.room_id == Room.room_id
    ).join(
        Hotel, Booking.hotel_id == Hotel.hotel_id
    ).filter(
        Booking.user_id == current_user.user_id,
        Booking.status == 'confirmed'
    ).order_by(Booking.booking_date.desc()).first()

    if not latest_booking:
        flash('No confirmed booking found.', 'error')
        return redirect(url_for('profile'))

    room = db.session.get(Room, latest_booking.room_id)
    if not room:
        flash('Room details not found.', 'error')
        return redirect(url_for('profile'))

    converted_price, symbol = convert_price(float(latest_booking.total_price), currency)
    
    return render_template('hotel_booked.html', 
                         booking=latest_booking,
                         hotel=latest_booking.hotel,
                         room=room,  # Pass the room object explicitly
                         number_of_guests=latest_booking.number_of_guests,
                         booking_id=latest_booking.booking_id,
                         converted_price=converted_price,
                         currency_symbol=symbol,
                         current_currency=currency)


@app.route('/download_receipt/<string:booking_id>')
@login_required
def download_receipt(booking_id):
    booking = Booking.query.filter_by(
        booking_id=booking_id,
        user_id=current_user.user_id
    ).first_or_404()

    buffer = io.BytesIO()

    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle(f"Booking Receipt - {booking.booking_id}")

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(100, 750, "Booking Receipt")
    pdf.setFont("Helvetica", 12)
    pdf.drawString(100, 720, f"Booking ID: {booking.booking_id}")
    pdf.drawString(100, 700, f"Hotel: {booking.hotel.name}")
    pdf.drawString(100, 680, f"Check-in: {booking.check_in_date}")
    pdf.drawString(100, 660, f"Check-out: {booking.check_out_date}")
    pdf.drawString(100, 640, f"Room Type: {booking.room.type_name}")
    pdf.drawString(100, 620, f"Guests: {booking.number_of_guests}")
    pdf.drawString(100, 600, f"Total Price: ${booking.total_price}")

    pdf.drawString(100, 560, "Thank you for choosing our service!")

    pdf.save()

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Booking_Receipt_{booking.booking_id}.pdf",
        mimetype='application/pdf'
    )

@app.route('/cancel_booking/<booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    if booking.user_id != current_user.user_id:
        flash('You are not authorized to cancel this booking.', 'error')
        return redirect(url_for('profile'))
    
    if booking.status == 'cancelled':
        flash('This booking is already cancelled.', 'error')
        return redirect(url_for('profile'))

    try:
        booking.status = 'cancelled'
        db.session.commit()
        flash('Booking cancelled successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while cancelling the booking.', 'error')
    
    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    confirmed_bookings = Booking.query.filter(
        Booking.user_id == current_user.user_id,
        Booking.status == 'confirmed'
    ).order_by(Booking.booking_date.desc()).all()

    if not confirmed_bookings:
        all_bookings = Booking.query.filter_by(user_id=current_user.user_id).all()
        print(f"All user bookings: {all_bookings}")
        flash('No confirmed booking found.', 'error')
        return render_template('profile.html', bookings=all_bookings)

    for booking in confirmed_bookings:
        print(f"Booking ID: {booking.booking_id}")
        print(f"Booking Hotel: {booking.hotel.name}")
        print(f"Booking Room: {booking.room.type_name}")

    return render_template('profile.html', 
                         bookings=confirmed_bookings)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    hotels = Hotel.query.all()
    
    bookings = db.session.query(
        Booking, User, Hotel
    ).join(
        User, Booking.user_id == User.user_id
    ).join(
        Hotel, Booking.hotel_id == Hotel.hotel_id
    ).all()
    
    users = User.query.all()
    
    hotel_revenues = db.session.query(
        Hotel.name,
        db.func.coalesce(db.func.sum(Booking.total_price), 0).label('total_revenue'),
        db.func.count(Booking.booking_id).label('booking_count')
    ).outerjoin(
        Booking, Hotel.hotel_id == Booking.hotel_id
    ).group_by(
        Hotel.hotel_id, Hotel.name
    ).all()

    return render_template('admin/dashboard.html',
                         hotels=hotels,
                         bookings=bookings,
                         users=users,
                         hotel_revenues=hotel_revenues)

@app.route('/admin/hotels')
@login_required
def admin_hotels():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    hotels = Hotel.query.all()
    return render_template('admin/hotels.html', hotels=hotels)

@app.route('/admin/hotel/<int:hotel_id>')
@login_required
def get_hotel(hotel_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    hotel = Hotel.query.get_or_404(hotel_id)
    return jsonify({
        'name': hotel.name,
        'city': hotel.city,
        'capacity': hotel.capacity,
        'about_paragraph': hotel.about_paragraph
    })

@app.route('/admin/hotel/add', methods=['POST'])
@login_required
def add_hotel():
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        name = request.form.get('name')
        city = request.form.get('city')
        capacity = request.form.get('capacity')
        about = request.form.get('about')
        
        image = request.files.get('image')
        image_url = '/img/default-hotel.jpg'  # Default image
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.static_folder, 'img', filename))
            image_url = f'/img/{filename}'
        
        hotel = Hotel(
            name=name,
            city=city,
            capacity=capacity,
            about_paragraph=about,
            image_url=image_url
        )
        
        db.session.add(hotel)
        db.session.commit()
        return jsonify({'message': 'Hotel added successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/hotel/edit/<int:hotel_id>', methods=['POST'])
@login_required
def edit_hotel(hotel_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        hotel = Hotel.query.get_or_404(hotel_id)
        hotel.name = request.form.get('name')
        hotel.city = request.form.get('city')
        hotel.capacity = request.form.get('capacity')
        hotel.about_paragraph = request.form.get('about')
        
        image = request.files.get('image')
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.static_folder, 'img', filename))
            hotel.image_url = f'/img/{filename}'
        
        db.session.commit()
        return jsonify({'message': 'Hotel updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/hotel/delete/<int:hotel_id>', methods=['POST'])
@login_required
def delete_hotel(hotel_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        hotel = Hotel.query.get_or_404(hotel_id)
        db.session.delete(hotel)
        db.session.commit()
        return jsonify({'message': 'Hotel deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/hotel/<int:hotel_id>/rooms')
@login_required
def manage_rooms(hotel_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    hotel = Hotel.query.get_or_404(hotel_id)
    rooms = Room.query.filter_by(hotel_id=hotel_id).all()
    return render_template('admin/manage_rooms.html', hotel=hotel, rooms=rooms)

@app.route('/api/room/<int:room_id>')
@login_required
def get_room(room_id):
    if current_user.role != 'admin':
        abort(403)
    
    room = Room.query.get_or_404(room_id)
    return jsonify({
        'base_rate': room.base_rate,
        'peak_rate': room.peak_rate,
        'off_peak_rate': room.off_peak_rate
    })

@app.route('/admin/room/edit/<int:room_id>', methods=['POST'])
@login_required
def edit_room(room_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    room = Room.query.get_or_404(room_id)
    try:
        room.base_rate = float(request.form['base_rate'])
        room.peak_rate = float(request.form['peak_rate'])
        room.off_peak_rate = float(request.form['off_peak_rate'])
        db.session.commit()
        flash('Room prices updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating room prices: {str(e)}', 'danger')
    
    return redirect(url_for('manage_rooms', hotel_id=room.hotel_id))

@app.route('/admin/revenue')
@login_required
def revenue_management():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    revenue_stats = db.session.query(
        db.func.sum(Booking.total_price).label('total_revenue'),
        db.func.count(Booking.booking_id).label('total_bookings')
    ).first()
    
    total_revenue = revenue_stats.total_revenue or 0
    total_bookings = revenue_stats.total_bookings or 0
    avg_booking_value = total_revenue / total_bookings if total_bookings > 0 else 0
    
    hotel_revenues = db.session.query(
        Hotel.name,
        Hotel.city,
        db.func.sum(Booking.total_price).label('total_revenue'),
        db.func.count(Booking.booking_id).label('booking_count')
    ).outerjoin(
        Booking, Hotel.hotel_id == Booking.hotel_id
    ).group_by(
        Hotel.hotel_id, Hotel.name, Hotel.city
    ).all()
    
    for revenue in hotel_revenues:
        revenue = revenue._asdict()
        revenue['avg_booking_value'] = (
            revenue['total_revenue'] / revenue['booking_count'] 
            if revenue['booking_count'] > 0 else 0
        )
    
    return render_template('admin/revenue.html',
                         total_revenue=total_revenue,
                         total_bookings=total_bookings,
                         avg_booking_value=avg_booking_value,
                         hotel_revenues=hotel_revenues)

@app.route('/admin/users')
@login_required
def user_management():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>/change-password', methods=['POST'])
@login_required
def change_user_password(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json()
    new_password = data.get('password')
    
    if not new_password:
        return jsonify({'error': 'Password is required'}), 400
    
    user = User.query.get_or_404(user_id)
    user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    
    try:
        db.session.commit()
        return jsonify({'message': 'Password updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


app.permanent_session_lifetime = timedelta(days=30)

with app.app_context():
    admin = User.query.filter_by(email='admin_hotel@gmail.com').first()
    
    if admin:
        admin.password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin.first_name = 'Admin'
        admin.last_name = 'User'
        admin.role = 'admin'
    else:
        admin = User(
            email='admin_hotel@gmail.com',
            password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
            first_name='Admin',
            last_name='User',
            role='admin'
        )
        db.session.add(admin)
    
    try:
        db.session.commit()
        print("Admin user ready with:")
        print("Email: admin_hotel@gmail.com")
        print("Password: admin123")
    except Exception as e:
        db.session.rollback()
        print(f"Error setting up admin: {str(e)}")

CURRENCY_RATES = {
    'USD': 1.0, 
    'GBP': 0.79, 
    'NPR': 132.95 
}

CURRENCY_SYMBOLS = {
    'USD': '$',
    'GBP': '£',
    'NPR': 'रू'
}

def convert_price(price, target_currency='USD'):
    """Convert price from USD to target currency"""
    if target_currency not in CURRENCY_RATES:
        return price, CURRENCY_SYMBOLS['USD']
    
    converted_price = price * CURRENCY_RATES[target_currency]
    return converted_price, CURRENCY_SYMBOLS[target_currency]

@app.context_processor
def inject_currency():
    currency = request.args.get('currency', 'USD')
    return dict(current_currency=currency)

if __name__ == '__main__':
    app.run(debug=True)
