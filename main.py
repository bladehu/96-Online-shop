import flask
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
import os
from forms import RegisterForm, LoginForm, AddCookieForm
import stripe
from decouple import config

# Stripe website
# https://dashboard.stripe.com/test/dashboard

app = Flask(__name__)
app.config['SECRET_KEY'] = "SECRET_KEY"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///cookies.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

stripe.api_key = config("stripe.api_key")

MY_DOMAIN = "http://127.0.0.1:5000/"

db = SQLAlchemy(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

line_item = []


class CookiesDB(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prod_id = db.Column(db.String(250), unique=True, nullable=False)
    price_id = db.Column(db.String(250), unique=True, nullable=False)
    name = db.Column(db.String(250), unique=True, nullable=False)
    description = db.Column(db.String(250), nullable=False)
    price = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return flask.abort(403)
        return function(*args, **kwargs)

    return decorated_function


@app.route('/', methods=["GET", "POST"])
def main_page():
    if request.method == "POST":
        line_item.append(
            {
                    'price': request.form["product-id"],
                    'quantity': int(request.form["amount"]),
                },
        )
    cookies = CookiesDB.query.all()
    users = User.query.all()
    return render_template("index.html", all_cookies=cookies, users=users, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        else:
            password_hashed_and_salted = generate_password_hash(
                password=form.password.data,
                method="pbkdf2:sha256",
                salt_length=8
            )
            new_user = User(
                email=form.email.data,
                password=password_hashed_and_salted,
                name=form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('main_page'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main_page'))


@app.route('/new-cookie', methods=["GET", "POST"], endpoint='add_new_cookies')
@admin_only
def add_new_cookies():
    form = AddCookieForm()
    if form.validate_on_submit():
        new_product = stripe.Product.create(
            description=form.description.data,
            images=[form.img_url.data],
            name=form.name.data,
        )
        new_price_for_product = stripe.Price.create(
            currency="usd",
            product=new_product.id,
            unit_amount=form.price.data
        )
        new_cookie = CookiesDB(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data,
            img_url=form.img_url.data,
            prod_id=new_product.id,
            price_id=new_price_for_product.id,
        )
        db.session.add(new_cookie)
        db.session.commit()
        return redirect(url_for('main_page'))
    return render_template('add-cookie.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/cart', methods=["GET", "POST"])
def cart():
    products_to_buy = []
    quantities = []
    totals = []
    print(line_item)
    for item in line_item:
        products_to_buy.append(CookiesDB.query.filter(CookiesDB.price_id == item["price"]).first())
        quantities.append(item["quantity"])
    length = len(products_to_buy)
    for i in range(length):
        totals.append(float(products_to_buy[i].price)*float(quantities[i]))
    session["grand_total"] = sum(totals)
    return render_template("cart.html", products=products_to_buy, quantity=quantities, len=length, totals=totals,
                           grand_total=sum(totals))


@app.route('/checkout', methods=["GET", "POST"])
def checkout():
    total = session["grand_total"]
    return render_template("checkout.html", total=total)


@app.route('/success', methods=["GET", "POST"])
def success():
    return render_template("success.html")


@app.route('/cancel', methods=["GET", "POST"])
def cancel():
    return render_template("cancel.html")


@app.route('/create-checkout-session', methods=["POST"])
def create_checkout_session():
    try:

        checkout_session = stripe.checkout.Session.create(
            line_items=line_item,
            mode='payment',
            success_url=MY_DOMAIN + 'success',
            cancel_url=MY_DOMAIN + 'cancel',
        )
    except Exception as e:
        return str(e)

    return redirect(checkout_session.url, code=303)


if __name__ == "__main__":
    app.run(debug=True)
