from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
import secrets
import csv
import os

# Initialize the Flask application
app = Flask(__name__)

# Configuration settings for the Flask app
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ipuser:qwe123@localhost/iptable'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize SQLAlchemy with the Flask app
db = SQLAlchemy(app)

# Initialize Flask-Migrate for database migrations
migrate = Migrate(app, db)

# Initialize Flask-Login for user session management
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define the User model for SQLAlchemy
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Define the IPTable model for SQLAlchemy
class IPTable(db.Model):
    __tablename__ = 'iptable'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Class_ = db.Column(db.String(255), name='Class')
    Gateway = db.Column(db.String(255))
    IPAddress = db.Column(db.String(255), name='IP Address')
    Host = db.Column(db.String(255))
    Part = db.Column(db.String(255))
    Name = db.Column(db.String(255))
    Place = db.Column(db.String(255))
    Phone = db.Column(db.String(255))
    Etcs = db.Column(db.String(255))
    Date = db.Column(db.String(255))
    Num = db.Column(db.String(255))

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define the login form using FlaskForm
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Define the registration form using FlaskForm
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

# Route for user registration, restricted to authorized users and IP addresses
@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    authorized_users = ['hguadmin', 'hch9133']
    authorized_ips = ['172.31.20.21']

    if current_user.username not in authorized_users or request.remote_addr not in authorized_ips:
        return "Access Denied. You are not authorized to access this page.", 403

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', form=form, error='Invalid username or password.')
    return render_template('login.html', form=form)

# Route for user logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Home route redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

# Dashboard route, accessible only by logged-in users
@app.route('/dashboard')
@login_required
def dashboard():
    authorized_users = ['hguadmin', 'hch9133']
    authorized_ips = ['172.31.20.21']
    can_register = current_user.username in authorized_users or request.remote_addr in authorized_ips
    return render_template('dashboard.html', can_register=can_register)

# IP management route, handles displaying and searching IP entries
@app.route('/ip_management', methods=['GET', 'POST'])
@login_required
def ip_management():
    page = request.args.get('page', 1, type=int)
    per_page = 1000  # Adjust as per your pagination needs
    pagination = IPTable.query.paginate(page=page, per_page=per_page, error_out=False)
    ips = pagination.items
    
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        if query:
            results = IPTable.query.filter(
                or_(
                    IPTable.Class_.ilike(f'%{query}%'),
                    IPTable.Gateway.ilike(f'%{query}%'),
                    IPTable.IPAddress.ilike(f'%{query}%'),
                    IPTable.Host.ilike(f'%{query}%'),
                    IPTable.Part.ilike(f'%{query}%'),
                    IPTable.Name.ilike(f'%{query}%'),
                    IPTable.Place.ilike(f'%{query}%'),
                    IPTable.Phone.ilike(f'%{query}%'),
                    IPTable.Etcs.ilike(f'%{query}%'),
                    IPTable.Date.ilike(f'%{query}%'),
                    IPTable.Num.ilike(f'%{query}%')
                )
            ).paginate(page=page, per_page=per_page, error_out=False)
            return render_template('ip_management.html', ips=results.items, pagination=results, query=query)
    
    return render_template('ip_management.html', ips=ips, pagination=pagination)

@app.route('/add', methods=['POST'])
@login_required
def add():
    new_ip = IPTable(
        Class_=request.form['Class_'],
        Gateway=request.form['Gateway'],
        IPAddress=request.form['IPAddress'],
        Host=request.form['Host'],
        Part=request.form['Part'],
        Name=request.form['Name'],
        Place=request.form['Place'],
        Phone=request.form['Phone'],
        Etcs=request.form['Etcs'],
        Date=request.form['Date'],
        Num=request.form['Num']
    )
    db.session.add(new_ip)
    db.session.commit()

    # Determine the last page after adding the new IP
    total_ips = IPTable.query.count()
    per_page = 1000  # Adjust as per your pagination needs
    last_page = (total_ips - 1) // per_page + 1

    # Redirect to IP management page with anchor to scroll to the newly added IP
    return redirect(url_for('ip_management', page=last_page, _anchor='add-success'))

# Route to edit an existing IP entry
@app.route('/edit/<int:id>', methods=['POST'])
@login_required
def edit(id):
    ip = IPTable.query.get_or_404(id)
    field = list(request.form.keys())[0]
    new_value = request.form[field]
    setattr(ip, field, new_value)
    db.session.commit()
    return '', 204

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    try:
        ip = IPTable.query.get_or_404(id)
        db.session.delete(ip)
        db.session.commit()
        return jsonify({'status': 'success'}), 204
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to delete IP address {id}: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to delete IP address'}), 500

# Route to search for IP entries
@app.route('/search', methods=['POST'])
def search():
    query = request.form.get('query', '').strip()

    if query:
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Adjust as per your pagination needs

        results = IPTable.query.filter(
            or_(
                IPTable.Class_.ilike(f'%{query}%'),
                IPTable.Gateway.ilike(f'%{query}%'),
                IPTable.IPAddress.ilike(f'%{query}%'),
                IPTable.Host.ilike(f'%{query}%'),
                IPTable.Part.ilike(f'%{query}%'),
		IPTable.Name.ilike(f'%{query}%'),
                IPTable.Place.ilike(f'%{query}%'),
                IPTable.Phone.ilike(f'%{query}%'),
                IPTable.Etcs.ilike(f'%{query}%'),
                IPTable.Date.ilike(f'%{query}%'),
                IPTable.Num.ilike(f'%{query}%')
            )
        ).paginate(page=page, per_page=per_page, error_out=False)

        return render_template('ip_management.html', ips=results.items, pagination=results, query=query)
    else:
        return redirect(url_for('ip_management'))

# Route to import IP entries from a CSV file
@app.route('/import_csv', methods=['POST'])
@login_required
def import_csv():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)
    
    if file:
        try:
            filename = secure_filename(file.filename)
            file.save(filename)
            
            with open(filename, 'r', encoding='utf-8-sig') as csv_file:
                csv_reader = csv.DictReader(csv_file)
                for row in csv_reader:
                    try:
                        new_ip = IPTable(
                            Class_=row['Class'],
                            Gateway=row['Gateway'],
                            IPAddress=row['IP Address'],
                            Host=row['Host'],
                            Part=row['Part'],
                            Name=row['Name'],
                            Place=row['Place'],
                            Phone=row['Phone'],
                            Etcs=row['Etcs'],
                            Date=row['Date'],
                            Num=row['Num']
                        )
                        db.session.add(new_ip)
                    except IntegrityError:
                        db.session.rollback()
                        flash(f"Skipping duplicate entry: {row}", 'warning')
                
                db.session.commit()
            flash('CSV file imported successfully', 'success')
        except Exception as e:
            flash(f'Failed to import CSV file: {str(e)}', 'danger')
        finally:
            os.remove(filename)  # Remove the file after processing

    return redirect(url_for('ip_management'))

# Route to rollback the last import operation
@app.route('/rollback_import', methods=['POST'])
@login_required
def rollback_import():
    try:
        db.session.rollback()
        flash('Imported data rollback successful', 'success')
    except Exception as e:
        flash(f'Failed to rollback imported data: {str(e)}', 'danger')
    
    return redirect(url_for('ip_management'))

# Route to bulk delete selected IP entries
@app.route('/bulk_delete', methods=['POST'])
@login_required
def bulk_delete():
    try:
        delete_ids = request.form.getlist('delete_ids')
        for id in delete_ids:
            ip = IPTable.query.get_or_404(id)
            db.session.delete(ip)
        db.session.commit()
        flash('Selected entries deleted successfully', 'success')
    except Exception as e:
        flash(f'Failed to delete entries: {str(e)}', 'danger')
    
    return redirect(url_for('ip_management'))

# Main entry point to run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

