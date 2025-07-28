import os
import requests
import random

from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from google_auth_oauthlib.flow import Flow

from forms import SignupForm, LoginForm, OTPForm
from models import db, User

# --- App Initialization and Configuration ---

# This line is required for local development on HTTP.
# In production with HTTPS, you should remove this.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

# --- Security Best Practice: Use Environment Variables for Secrets ---
# You should set these in your terminal or a .env file, not hardcode them.
# Example: export SECRET_KEY='your_random_secret_key'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-default-secret-key-for-dev-only')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///biolink.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Mail Configuration (Use Environment Variables) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') # IMPORTANT: Set this environment variable
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') # IMPORTANT: Set this environment variable
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

# --- Google OAuth Configuration ---
# Create a 'client_secret.json' file in your project root or set the environment variables.
CLIENT_SECRET_FILE = 'client_secret.json'
REDIRECT_URI = 'http://127.0.0.1:5000/callback'
SCOPES = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email', 'openid']

# --- Initialize Extensions ---
mail = Mail(app)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# --- User Loader and Helper Functions ---

@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database for Flask-Login."""
    return User.query.get(int(user_id))

def send_otp(email, otp):
    """Sends an OTP to the user's email."""
    try:
        msg = Message('Your BioLink Verification Code', recipients=[email])
        msg.body = f'Your One-Time Password (OTP) for account verification is: {otp}'
        mail.send(msg)
    except Exception as e:
        # In a real app, you'd want to log this error more robustly.
        print(f"Error sending email: {e}")
        flash("We could not send the verification email. Please check your configuration.", "error")

def get_google_flow():
    """Initializes and returns a Google OAuth Flow object."""
    return Flow.from_client_secrets_file(
        client_secrets_file=CLIENT_SECRET_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

# --- Standard Authentication Routes (Email/Password) ---

@app.route('/')
def index():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = SignupForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("This email address is already registered. Please log in.", "warning")
            return redirect(url_for("login"))
        
        otp = str(random.randint(100000, 999999))
        session['signup_data'] = {
            'name': form.name.data,
            'email': form.email.data,
            'password': generate_password_hash(form.password.data, method='pbkdf2:sha256'),
            'otp': otp
        }

        send_otp(form.email.data, otp)
        flash("An OTP has been sent to your email. Please verify to complete signup.", "info")
        return redirect(url_for("verify"))

    return render_template("signup.html", form=form)

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = OTPForm()
    signup_data = session.get('signup_data')

    if not signup_data:
        flash("Your session has expired. Please sign up again.", "error")
        return redirect(url_for("signup"))

    if form.validate_on_submit():
        if form.otp.data == signup_data['otp']:
            new_user = User(
                name=signup_data['name'],
                email=signup_data['email'],
                password=signup_data['password'],
                is_verified=True
            )
            db.session.add(new_user)
            db.session.commit()
            session.pop('signup_data', None) # Clear session data
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid OTP. Please try again.", "error")
    
    return render_template("verify.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Check if user exists, has a password, and the password is correct
        if user and user.password and check_password_hash(user.password, form.password.data):
            if not user.is_verified:
                flash("Your account is not verified. Please complete the OTP verification.", "warning")
                # You could add a "resend OTP" feature here.
                return redirect(url_for("signup"))
            
            login_user(user)
            flash(f"Welcome back, {user.name}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password. Please try again.", "error")
    
    return render_template("login.html", form=form)

# --- Google OAuth Routes ---

@app.route("/google/login")
def google_login():
    """Redirects to Google's authorization page."""
    flow = get_google_flow()
    authorization_url, state = flow.authorization_url()
    session["state"] = state  # Store state to prevent CSRF attacks
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    """Handles the callback from Google after authentication."""
    flow = get_google_flow()
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        flash("State mismatch. Possible CSRF attack.", "error")
        return redirect(url_for("login"))

    credentials = flow.credentials
    # Use the token to get user info from Google's userinfo endpoint
    response = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={'Authorization': f'Bearer {credentials.token}'}
    )
    user_info = response.json()

    google_id = user_info['sub']
    email = user_info['email']
    name = user_info.get('name', 'User')
    picture = user_info.get('picture')

    # Find or create the user in the database
    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        # If no user with this google_id, check if one exists with the same email
        user = User.query.filter_by(email=email).first()
        if not user:
            # If no user exists at all, create a new one
            user = User(
                google_id=google_id,
                name=name,
                email=email,
                profile_pic_url=picture,
                is_verified=True  # Google accounts are considered verified
            )
            db.session.add(user)
        else:
            # If user with email exists, link their Google account
            user.google_id = google_id
            user.profile_pic_url = picture
            user.is_verified = True # Mark as verified if they link Google
    
    db.session.commit()
    login_user(user)
    flash(f"Successfully logged in as {user.name} via Google.", "success")
    return redirect(url_for("dashboard"))

# --- Application Routes ---

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route('/ai_prediction')
@login_required
def ai_prediction():
    return render_template("ai-prediction.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been successfully logged out.", "success")
    return redirect(url_for("index"))

# --- Run Application ---
if __name__ == "__main__":
    app.run(debug=True)
