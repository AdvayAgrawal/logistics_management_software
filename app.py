from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy()
login_manager = LoginManager(app)
login_manager.login_view = 'login'
print(app.config)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='user')  # Default role is 'user'

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(50), nullable=False)
    products = db.Column(db.String(200), nullable=False)  #csv
    status = db.Column(db.String(20), default='processing')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    quantity = db.Column(db.Integer, nullable=False)
    threshold = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('user', 'User'), ('inventory_manager', 'Inventory Manager')], default='user')
    submit = SubmitField('Sign Up')


class OrderForm(FlaskForm):
    customer_name = StringField('Customer Name', validators=[DataRequired(), Length(min=2, max=50)])
    products = StringField('Products (comma-separated)', validators=[DataRequired(), Length(min=2, max=200)])
    submit = SubmitField('Create Order')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired(), Length(min=2, max=50)])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    threshold = IntegerField('Threshold', validators=[DataRequired()])
    submit = SubmitField('Add Product')

def update_inventory(products):
    product_list = [product.strip() for product in products.split(',')]
    
    for product_name in product_list:
        product = Product.query.filter_by(name=product_name).first()
        if product:
            product.quantity -= 1  # Assuming each order decreases the quantity by 1
            if product.quantity < product.threshold:
                # Trigger an alert (you can handle alerts based on your requirements)
                flash(f'Alert: Inventory for {product.name} is below the threshold!', 'warning')
        else:
            # Handle the case where the product is not found in the inventory
            flash(f'Error: Product {product_name} not found in inventory!', 'danger')
            
    db.session.commit()

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'user':
        # For regular users, only show orders
        orders = Order.query.all()
        return render_template('dashboard.html', orders=orders)
    elif current_user.role == 'inventory_manager':
        # For inventory managers, show orders, inventory, and alerts
        orders = Order.query.all()
        products = Product.query.all()
        low_inventory_products = Product.query.filter(Product.quantity < Product.threshold).all()
        return render_template('dashboard.html', orders=orders, products=products, low_inventory_products=low_inventory_products)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create_order', methods=['GET', 'POST'])
@login_required
def create_order():
    form = OrderForm()
    if form.validate_on_submit():
        new_order = Order(customer_name=form.customer_name.data, products=form.products.data)
        db.session.add(new_order)
        db.session.commit()

        if current_user.role == 'inventory_manager':
            # If the user is an inventory manager, update inventory
            update_inventory(new_order.products)

        flash('Order created successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_order.html', form=form)

@app.route('/inventory')
@login_required
def inventory():
    products = Product.query.all()
    return render_template('inventory.html', products=products)

@app.route('/alerts')
@login_required
def alerts():
    # Retrieve products that are below the threshold
    low_inventory_products = Product.query.filter(Product.quantity < Product.threshold).all()
    return render_template('alerts.html', low_inventory_products=low_inventory_products)

@app.route('/view_orders')
@login_required
def view_orders():
    orders = Order.query.all()
    return render_template('view_orders.html', orders=orders)


if __name__ == '__main__':
    db.init_app(app)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
