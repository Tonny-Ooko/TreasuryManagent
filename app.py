from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import re
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
import mysql.connector
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.secret_key = 'your_secret_key'

users = {}
# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD']  = ''
app.config['MYSQL_DB'] = 'regsda'

# Configure the SQLAlchemy part of the application
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/welfare_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

mysql = MySQL(app)
db = SQLAlchemy(app)

class ResdaUser(db.Model):
    __bind_key__ = 'resda'
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)

class WelfareUser(db.Model):
    __bind_key__ = 'welfare_db'
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
# Models
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    mpesa_phone = db.Column(db.String(15), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    membership = db.Column(db.Enum('Single', 'Couple'), nullable=False)
    registration_date = db.Column(db.Date, default=db.func.current_date())
    last_login = db.Column(db.TIMESTAMP, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

class WelfareSubscription(db.Model):
    __tablename__ = 'welfare_subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subscription_type = db.Column(db.Enum('Monthly', 'Annual'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)

class SubscriptionRenewal(db.Model):
    __tablename__ = 'subscription_renewals'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    renewal_date = db.Column(db.Date, nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    renewal_status = db.Column(db.Enum('Pending', 'Completed'), default='Pending')

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CampMeetingOffering(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mpesa_phone = db.Column(db.String(15), nullable=False)
    camp_offering = db.Column(db.Numeric(10, 2), nullable=False)
    camp_expenses = db.Column(db.Numeric(10, 2), nullable=False)
    church_building_development = db.Column(db.Numeric(10, 2), nullable=False)
    amo_awmo_ambassador_children = db.Column(db.Enum('AMO', 'Adventist Women Ministry', 'Ambassador', 'Children'), nullable=False)
    cluster_range = db.Column(db.Enum('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', 'Guest'), nullable=False)
    local_church_budget_aemr = db.Column(db.Numeric(10, 2), nullable=False)
    total = db.Column(db.Numeric(10, 2), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

def sync_emails():
    # Fetch all users from resda
    resda_users = ResdaUser.query.all()

    for resda_user in resda_users:
        # Check if the email already exists in welfare_db
        welfare_user = WelfareUser.query.filter_by(email=resda_user.email).first()

        if not welfare_user:
            # If the email doesn't exist, add it to the welfare_db
            new_welfare_user = WelfareUser(email=resda_user.email)
            db.session.add(new_welfare_user)

    db.session.commit()
    print("Emails synchronized successfully!")

# Example route to trigger synchronization
@app.route('/sync-emails')
def sync_emails_route():
    sync_emails()
    return "Emails synchronized!"

@app.route('/camp_meeting', methods=['GET', 'POST'])
def camp_meeting():
    if request.method == 'POST':
        mpesa_phone = request.form['mpesa_phone']

        # Handle optional fields with default value handling
        camp_offering_str = request.form.get('camp_offering', '')
        camp_offering = float(camp_offering_str) if camp_offering_str else 0.0

        camp_expenses_str = request.form.get('camp_expenses', '')
        camp_expenses = float(camp_expenses_str) if camp_expenses_str else 0.0

        church_building_development_str = request.form.get('church_building_development', '')
        church_building_development = float(church_building_development_str) if church_building_development_str else 0.0

        local_church_budget_aemr_str = request.form.get('local_church_budget_aemr', '')
        local_church_budget_aemr = float(local_church_budget_aemr_str) if local_church_budget_aemr_str else 0.0

        amo_awmo_ambassador_children = request.form.get('amo_awmo_ambassador_children', '')
        cluster_range = request.form.get('cluster_range', '')

        # Calculate the total
        total = camp_offering + camp_expenses + church_building_development + local_church_budget_aemr

        # Create a new offering record
        new_offering = CampMeetingOffering(
            mpesa_phone=mpesa_phone,
            camp_offering=camp_offering,
            camp_expenses=camp_expenses,
            church_building_development=church_building_development,
            amo_awmo_ambassador_children=amo_awmo_ambassador_children,
            cluster_range=cluster_range,
            local_church_budget_aemr=local_church_budget_aemr,
            total=total
        )

        try:
            db.session.add(new_offering)
            db.session.commit()
            flash('Offering submitted successfully!', 'success')
            return redirect(url_for('camp_meeting'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('camp_meeting'))

    return render_template('camp_meeting.html')


# Route for home page
@app.route('/')
def home():
    return render_template('home.html')

def contains_consecutive_characters(password):
    """
    Checks if the password contains consecutive numbers, letters, or symbols.
    """
    for i in range(len(password) - 2):
        if ord(password[i]) + 1 == ord(password[i + 1]) and ord(password[i + 1]) + 1 == ord(password[i + 2]):
            return True
    return False

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Sanitize and strip input data
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()  # Normalize email to lowercase
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()
        membership = request.form['membership'].strip()

        # Check if the name contains at least two words
        if len(name.split()) < 2:
            flash('Please enter both your first and last name.')
            return render_template('register.html')

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!')
            return render_template('register.html')

        # Validate email format
        email_regex = r'^\S+@\S+\.\S+$'
        if not re.match(email_regex, email):
            flash('Invalid email format', 'danger')
            return render_template('register.html')

        # Validate password strength
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$'
        if not re.match(password_regex, password):
            flash('Password must be at least 6 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character', 'danger')
            return render_template('register.html')

        # Check for consecutive numbers, letters, or symbols in the password
        if contains_consecutive_characters(password):
            flash('Password cannot contain consecutive numbers, letters, or symbols.', 'danger')
            return render_template('register.html')

        # Check if the user already exists
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s OR name = %s", (email, name))
        existing_user = cur.fetchone()
        if existing_user:
            cur.close()
            flash('User already exists. Please log in.', 'danger')
            return render_template('register.html')

        # Hash the password using the same hashing method used in the login process
        hashed_password = generate_password_hash(password)
        password_set_date = datetime.utcnow()

        # Insert sanitized data into MySQL
        cur.execute("INSERT INTO users(name, email, password, membership, password_set_date) VALUES(%s, %s, %s, %s, %s)",
                    (name, email, hashed_password, membership, password_set_date))
        mysql.connection.commit()
        cur.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Sanitize and normalize input data
        email = request.form['email'].strip().lower()  # Normalize email to lowercase
        password = request.form['password'].strip()
        from_homepage = request.form.get('from_homepage', False)  # Check if the form is from the homepage

        # Debugging: Print the login attempt details
        print(f"Login attempt: email={email}, password={password}")

        # Fetch user from the `regsda` database
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            # Access fields using the correct tuple index
            db_password = user[3]  # Assuming 'password' is the 4th field in the `regsda` users table
            password_set_date = user[5]  # Assuming 'password_set_date' is the 6th field in the `regsda` users table

            # Debugging: Print the retrieved password hash and date
            print(f"User found: email={email}, db_password={db_password}, password_set_date={password_set_date}")

            if check_password_hash(db_password, password):
                # Store email in session
                session['user_email'] = email

                # Check if the password has expired (90 days after `password_set_date`)
                if datetime.utcnow().date() > (password_set_date + timedelta(days=90)):
                    flash('Your password has expired. Please update your password.')
                    return redirect('/change-password')

                # Fetch user ID from the `welfare` database
                welfare_user = User.query.filter_by(email=email).first()

                if welfare_user:
                    # Check for pending renewals
                    renewals = SubscriptionRenewal.query.filter_by(user_id=welfare_user.id, renewal_status='Pending').all()
                    if renewals:
                        for renewal in renewals:
                            flash(f'Renewal reminder: Your subscription of Ksh {renewal.amount} is pending since {renewal.renewal_date}.', 'warning')
                            new_notification = Notification(user_id=welfare_user.id, message=f'Renewal reminder: Your subscription of Ksh {renewal.amount} is pending since {renewal.renewal_date}.')
                            db.session.add(new_notification)

                    # Check for expired subscriptions
                    subscriptions = WelfareSubscription.query.filter_by(user_id=welfare_user.id).all()
                    for subscription in subscriptions:
                        if subscription.end_date < datetime.utcnow():
                            flash(f'Your subscription has expired. Please renew to continue.', 'danger')
                            new_renewal = SubscriptionRenewal(user_id=welfare_user.id, renewal_date=datetime.utcnow(), amount=subscription.amount)
                            db.session.add(new_renewal)

                    db.session.commit()

                flash('Login successful!')
                return redirect('/offering')
            else:
                print(f"Invalid password for user: {email}")
                flash('Invalid credentials.')
        else:
            print(f"No user found with email: {email}")
            flash('Invalid credentials.')

        # If the login fails and the form is from the homepage, render the homepage with the error message
        if from_homepage:
            return render_template('home.html')

    return render_template('login.html')



@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_email' not in session:
        flash('Please log in first.')
        return redirect('/login')

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        if new_password != confirm_new_password:
            flash('Passwords do not match!')
            return render_template('change_password.html')

        hashed_password = generate_password_hash(new_password)
        password_set_date = datetime.utcnow()

        # Update the user's password and password_set_date in the database
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET password = %s, password_set_date = %s WHERE email = %s",
                    (hashed_password, password_set_date, session['user_email']))
        mysql.connection.commit()
        cur.close()

        flash('Password updated successfully! Please log in with your new password.')
        return redirect('/login')

    return render_template('change_password.html')


@app.route('/offering', methods=['GET', 'POST'])
def offering():
    if request.method == 'POST':
        mpesa_phone = request.form['mpesa_phone']
        god_tithe = float(request.form['god_tithe'])
        combined_offering = float(request.form['combined_offering'])
        thanksgiving = float(request.form['thanksgiving'])
        total = god_tithe + combined_offering + thanksgiving

        # Save the offering details to the database
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO offerings (mpesa_phone, god_tithe, combined_offering, thanksgiving, total) VALUES (%s, %s, %s, %s, %s)",
                       (mpesa_phone, god_tithe, combined_offering, thanksgiving, total))
        mysql.connection.commit()
        cursor.close()

        flash('Offering details recorded successfully!')
        return redirect('/offering')

    return render_template('offering.html')

@app.route('/welfare-registration', methods=['GET', 'POST'])
def welfare_registration():
    if request.method == 'POST':
        mpesa_phone = request.form['mpesa_phone']
        name = request.form['name']
        welfare_subscription = request.form['welfare_subscription']

        # Ensure name has at least two parts
        if len(name.split()) < 2:
            flash('Please enter at least two names.', 'error')
            return redirect(url_for('welfare_registration'))

        # Determine the amount and subscription period
        amount = 0
        subscription_type = None
        end_date = None
        if welfare_subscription == '300':
            amount = 300
            subscription_type = 'Monthly'
            end_date = datetime.utcnow() + timedelta(days=30)
        elif welfare_subscription == '3600':
            amount = 3600
            subscription_type = 'Annual'
            end_date = datetime.utcnow() + timedelta(days=365)
        elif welfare_subscription == '500':
            amount = 500
            subscription_type = 'Monthly'
            end_date = datetime.utcnow() + timedelta(days=30)
        elif welfare_subscription == '6000':
            amount = 6000
            subscription_type = 'Annual'
            end_date = datetime.utcnow() + timedelta(days=365)
        else:
            flash('Invalid subscription amount.', 'error')
            return redirect(url_for('welfare_registration'))

        try:
            # Check if email already exists
            existing_user = User.query.filter_by(email="example@example.com").first()
            if existing_user:
                flash('Email already exists. Please use a different email.', 'error')
                return redirect(url_for('welfare_registration'))

            # Create new user and subscription
            new_user = User(mpesa_phone=mpesa_phone, name=name, password="hashed_password", email="example@example.com", membership='Single')
            db.session.add(new_user)
            db.session.commit()

            new_subscription = WelfareSubscription(user_id=new_user.id, subscription_type=subscription_type, amount=amount, start_date=datetime.utcnow(), end_date=end_date)
            db.session.add(new_subscription)
            db.session.commit()

            flash(f'Registration successful! Total amount: Ksh {amount}', 'success')
            return redirect(url_for('success_page'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('welfare_registration'))

    return render_template('welfare_registration.html')


@app.route('/evangelism-offerings', methods=['GET', 'POST'])
def evangelism_offerings():
    if request.method == 'POST':
        mpesa_phone = request.form['mpesa_phone']
        church_evangelism = request.form['church_evangelism'] or 0
        conference_evangelism = request.form['conference_evangelism'] or 0
        station_fund = 200  # Fixed amount for Station Fund
        others = request.form['others'] or 0
        total = float(church_evangelism) + float(conference_evangelism) + station_fund + float(others)

        conn = mysql.connection
        cursor = conn.cursor()

        cursor.execute('''INSERT INTO evangelism_offerings 
                          (mpesa_phone, church_evangelism, conference_evangelism, station_fund, others, total) 
                          VALUES (%s, %s, %s, %s, %s, %s)''',
                          (mpesa_phone, church_evangelism, conference_evangelism, station_fund, others, total))
        conn.commit()
        cursor.close()

        flash('Your offering has been recorded successfully!')
        return redirect(url_for('evangelism_offerings'))

    return render_template('evangelism_offerings.html')

if __name__ == '__main__':
    app.run(debug=True)
