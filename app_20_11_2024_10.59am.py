import os
import mysql.connector
from mysql.connector import Error, ProgrammingError
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, jsonify
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Define a secret key for session management
serializer = URLSafeTimedSerializer(app.secret_key)

# Replace 'your_credentials.json' with the path to your downloaded credentials file
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Required for testing only, remove for production
flow = Flow.from_client_secrets_file(
    'credentials.json',
    scopes=['https://www.googleapis.com/auth/gmail.send'],
    redirect_uri='http://localhost:5000/callback'
)

# MySQL connection configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_DATABASE'] = 'db'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'poon@psm16828'

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587 #มีสอนอยู่นะ
app.config['MAIL_USERNAME'] = 'poonnawat.project@gmail.com'  # Use your actual Gmail address ใช้mail มึงก็ได้
app.config['MAIL_PASSWORD'] = 'mmge jtjl gaes gnde'  # Use your generated App Password หรือ จะเจนเองก็ได้
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

#session credential configuration
session['credentials'] = {
    'token': credentials.token,
    'refresh_token': credentials.refresh_token,
    'token_uri': credentials.token_uri,
    'client_id': credentials.client_id,
    'client_secret': credentials.client_secret,
    'scopes': credentials.scopes
}

#Google API client: https://developers.google.com/
service = build('gmail', 'v1', credentials=credentials)



# Function to establish a database connection
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            database=app.config['MYSQL_DATABASE'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD']
        )
        if connection.is_connected():
            print('Connected to database.')
            return connection
    except Error as e:
        print(f"Error: {e}")
    return None

# Verify password helper function
def verify_password(stored_password_hash, provided_password):
    return check_password_hash(stored_password_hash, provided_password)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            try:
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()
                if user and verify_password(user['password_hash'], password):
                    session['user_id'] = user['user_id']  # Store user ID in session
                    flash('Login successful', 'success')
                    return redirect(url_for('user_profile'))
                else:
                    flash('Invalid email or password', 'danger')
            except ProgrammingError as e:
                print(f"ProgrammingError: {e}")
                flash('Database query error.', 'danger')
            finally:
                cursor.close()
                connection.close()
        else:
            flash('Database connection error.', 'danger')
    
    return render_template('login.html')

# initiates the OAuth 2.0 flow by generating the authorization URL and redirecting the user to the Google consent screen.
@app.route('/authorize')
def authorize():
    authorization_url, state = flow.authorization_url()
    
    # Store the state in the session to validate the response later
    session['state'] = state
    
    return redirect(authorization_url)


#processes the response from Google after the user grants or denies permissions. It fetches the token and prepares credentials for API usage.
@app.route('/callback')
def callback():
    try:
        # Verify the state to prevent CSRF attacks
        if request.args.get('state') != session.get('state'):
            flash('Invalid state parameter', 'danger')
            return redirect(url_for('index'))

        # Exchange the authorization code for tokens
        flow.fetch_token(authorization_response=request.url)

        # Retrieve the credentials object
        credentials = flow.credentials

        # Store credentials in the session or securely in a database
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }

        flash('Authorization successful! You can now access Google APIs.', 'success')
    except Exception as e:
        flash(f'Error during callback processing: {e}', 'danger')

    # Redirect the user to the home page or a specific page
    return redirect(url_for('index'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Here you would typically look up the user by email
        # For demonstration purposes, let's assume it always succeeds.
        
        # Generate a password reset token
        token = serializer.dumps(email, salt='password-reset-salt')
        reset_url = url_for('reset_password', token=token, _external=True)

        # Send the email
        msg = Message('Password Recovery', recipients=[email])
        msg.body = f'Click the link to reset your password: {reset_url}'
        mail.send(msg)

        flash('A recovery email has been sent!', 'success')
        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/send_recovery_email', methods=['POST'])
def send_recovery_email():
    email = request.form['email']
    
    # Establish a database connection
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            # Check if the email exists in the database
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()  # Fetch the user record
            
            if user:
                # Generate a password reset token
                token = serializer.dumps(email, salt='password-reset-salt')
                recovery_url = url_for('reset_password', token=token, _external=True)
                
                # Prepare and send the email
                msg = Message(
                    subject='Password Recovery',
                    sender='poonnawat.project@gmail.com',  # Ensure this matches MAIL_USERNAME
                    recipients=[email]  # Must be a list
                )
                msg.body = f"Click the link to reset your password: {recovery_url}"
                mail.send(msg)
                
                flash('A password reset link has been sent to your email.', 'success')
            else:
                flash('Email not found.', 'danger')
        except Exception as e:
            print(f"Error: {e}")  # Log the error for debugging
            flash('An error occurred while processing your request.', 'danger')
        finally:
            cursor.close()
            connection.close()  # Ensure the connection is closed
    else:
        flash('Database connection error.', 'danger')
    
    return redirect(url_for('login'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            try:
                hashed_password = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", 
                               (hashed_password, email))
                connection.commit()
                flash('Your password has been updated!', 'success')
                return redirect(url_for('login'))
            except ProgrammingError as e:
                print(f"ProgrammingError: {e}")
                flash('Database query error.', 'danger')
            finally:
                cursor.close()
                connection.close()
        else:
            flash('Database connection error.', 'danger')
    
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.clear()  # Clear the session
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
        else:
            connection = get_db_connection()
            if connection:
                cursor = connection.cursor(dictionary=True)
                try:
                    # Check for existing email
                    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                    user_email = cursor.fetchone()

                    # Check for existing username
                    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                    user_username = cursor.fetchone()

                    if user_email:
                        flash('Email already exists', 'danger')
                    elif user_username:
                        flash('Username already exists', 'danger')
                    else:
                        # Store password hash
                        hashed_password = generate_password_hash(password)
                        cursor.execute(
                            "INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)", 
                            (email, username, hashed_password)
                        )
                        connection.commit()
                        flash('Signup successful', 'success')
                        return redirect(url_for('login'))
                except ProgrammingError as e:
                    print(f"ProgrammingError: {e}")
                    flash('Database query error.', 'danger')
                finally:
                    cursor.close()
                    connection.close()
            else:
                flash('Database connection error.', 'danger')

    return render_template('signup.html')

# Single definition of /order route
@app.route('/order')
def order():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM products")
            products = cursor.fetchall()
            return render_template('order.html', products=products)
        except ProgrammingError as e:
            print(f"ProgrammingError: {e}")
            flash('Error retrieving products.', 'danger')
        finally:
            cursor.close()
            connection.close()
    else:
        flash('Database connection error.', 'danger')
    
    return render_template('order.html', products=[])

@app.route('/add_product', methods=['POST'])
def add_product():
    # Use request.form.get() to access form data
    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    category = request.form.get('category')
    stock_quantity = request.form.get('stock_quantity')
    image_file = request.files['image']

    # Define the image directory
    image_folder = 'static/images'
    if not os.path.exists(image_folder):
        os.makedirs(image_folder)

    # Save the image file
    image_url = os.path.join(image_folder, image_file.filename)
    image_file.save(image_url)

    # Establish the database connection
    connection = get_db_connection()
    cursor = connection.cursor()

    # Insert product with image path and other details
    cursor.execute("""
        INSERT INTO products (name, description, price, category, image_url, stock_quantity)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (name, description, price, category, image_url, stock_quantity))

    connection.commit()
    cursor.close()
    connection.close()

    return redirect(url_for('order'))

@app.route('/order/<int:product_id>', methods=['GET'])
def get_product_details(product_id):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            # Fetch product details from the database using product_id
            cursor.execute('SELECT * FROM products WHERE product_id = %s', (product_id,))
            product = cursor.fetchone()

            # Check if product exists
            if product is None:
                flash('Product not found', 'danger')
                return render_template('404.html'), 404  # Render a 404 page if product doesn't exist

            # Debugging: Flash the image path for verification
            image_path = product.get('image_url', None)
            if image_path:
                flash(f"Image path from database: {image_path}", 'info')
            else:
                flash("No image path found for this product in the database.", 'warning')

            # Render the product detail template
            return render_template('product_detail.html', product=product)
        finally:
            cursor.close()
            connection.close()
    else:
        flash('Database connection error', 'danger')
        return render_template('error.html'), 500  # Render an error page if database connection fails


@app.route('/cart')
def cart():
    return render_template('cart.html')

@app.route('/support')
def support():
    return render_template('support.html')

@app.route('/user_profile', methods=['GET', 'POST'])
def user_profile():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('Please log in to access your profile.', 'danger')
        return redirect(url_for('login'))
    #flash(f'Debugging: Your user ID is {session['user_id']}', 'info')
    
    # Connect to the database
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    user_id = session['user_id']
    if not connection:
        flash('Database connection error.', 'danger')
        return redirect(url_for('home'))  # Redirect to a safe page

    
    # Handle form submission (Edit Profile)
    if request.method == 'POST':
        # Fetch data from the form
        user_id = session['user_id']
        username = request.form['username']
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        address = request.form['address']
        phone_number = request.form['phone_number']
        # SQL query to update the user's profile in the database
        try:
            sql = '''UPDATE users
         SET username = %s, email = %s, first_name = %s, last_name = %s, address = %s, phone_number = %s 
         WHERE user_id = %s'''
# Pass all parameters as a single tuple
            cursor.execute(sql, (username, email, first_name, last_name, address, phone_number, user_id))
            connection.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            print(f"Error: {e}")
            flash(f'Error updating profile.{e}', 'info')
        finally:
            cursor.close()
            connection.close()

        return redirect(url_for('user_profile'))  # Reload the page after updating

    # Handle GET request (Display Profile)
    try:
        cursor.execute('''SELECT * FROM users WHERE user_id = %s''',(user_id,)) #(user_id,) to use it as tuple
        user = cursor.fetchone()
    except ProgrammingError as e:
        print(f"ProgrammingError: {e}")
        flash('Error retrieving user profile.', 'danger')
        user = None
    finally:
        cursor.close()
        connection.close()
        
    if user is None:
        flash('User not found.','danger')
        return redirect(url_for('home'))

    # Render the template with the user data
    return render_template('user_profile.html', user=user)

@app.route('/searchbar')
def searchbar():
    return render_template('searchbar.html')

if __name__ == '__main__':
    app.run(debug=True)
