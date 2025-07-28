from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo

class SignupForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired(), Length(min=2, max=100)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[InputRequired(), EqualTo("password")])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Log In")

class OTPForm(FlaskForm):
    otp = StringField("Enter OTP", validators=[InputRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verify OTP")