from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
import stripe
stripe.api_key = "sk_test_51L6FjlCuR4afO074wiwyhUu74xdve7mqhR7ZPPBoG1mTslJhaolXDj9OvowJ" \
                 "J4Bm7z0eKXOO1bcupxCQXxm76DNR00xsgFBDZI"


class RegisterForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    name = StringField(label="Name", validators=[DataRequired()])
    submit = SubmitField(label="Register")


class LoginForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="Login")


class AddCookieForm(FlaskForm):
    name = StringField(label="New Cookie name", validators=[DataRequired()])
    description = StringField(label="Short description of the product", validators=[DataRequired()])
    price = StringField(label="Price", validators=[DataRequired()])
    img_url = StringField(label="Cookie picture URL", validators=[DataRequired(), URL()])
    submit = SubmitField(label="Add Cookie")
