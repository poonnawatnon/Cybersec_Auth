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
from flask_cors import CORS
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import validate_csrf

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.config['SECRET_KEY'] = 'poon@psm16828'  # Set a secret key for session management (must secure)
csrf = CSRFProtect(app)
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

# Flask-Mail configuration (search instruction yourself)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587 
app.config['MAIL_USERNAME'] = 'poonnawat.project@gmail.com'  # Use your actual Gmail address ใช้mail ก็ได้
app.config['MAIL_PASSWORD'] = 'mmge jtjl gaes gnde'  # Use your generated App Password หรือ จะเจนเองก็ได้
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

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
@app.route('/order', methods=['GET'])
def order():
    connection = get_db_connection()
    
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            # Fetch sort parameter from query string (defaults to price_asc)
            sort_by = request.args.get('sort', default='price_asc', type=str)
            limit = request.args.get('limit', default=5, type=int)  # Number of products per page
            
            # Build the SQL query based on sorting
            if sort_by == 'price_asc':
                order_by_clause = 'ORDER BY price ASC'
            elif sort_by == 'price_desc':
                order_by_clause = 'ORDER BY price DESC'
            elif sort_by == 'name_asc':
                order_by_clause = 'ORDER BY name ASC'
            elif sort_by == 'name_desc':
                order_by_clause = 'ORDER BY name DESC'
            else:
                order_by_clause = ''
            
            # SQL query to fetch products with sorting and limiting
            cursor.execute(f"SELECT * FROM products {order_by_clause} LIMIT {limit}")
            products = cursor.fetchall()
            
            return render_template('order.html', products=products, sort_by=sort_by, limit=limit)
        
        except Exception as e:
            print(f"Error: {e}")
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

#gaming pc
@app.route('/gaming-pcs', methods=['GET'])
def gaming_pcs():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM gaming_pcs")
    pcs = cursor.fetchall()
    cursor.close()
    connection.close()
    return render_template('gaming_pcs.html', pcs=pcs)

@app.route('/add-gaming-pc', methods=['GET', 'POST'])
def add_gaming_pc():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        condition = request.form['condition']
        price = request.form['price']
        seller_id = request.form['seller_id']  # For example, this can be the logged-in user's ID
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("INSERT INTO gaming_pcs (title, description, condition, price, seller_id) VALUES (%s, %s, %s, %s, %s)", 
                       (title, description, condition, price, seller_id))
        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for('gaming_pcs'))
    return render_template('add_gaming_pc.html')

#pc specifications
@app.route('/pc-specifications/<pc_id>', methods=['GET', 'POST'])
def pc_specifications(pc_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if request.method == 'POST':
        cpu = request.form['cpu']
        gpu = request.form['gpu']
        ram = request.form['ram']
        storage = request.form['storage']
        motherboard = request.form['motherboard']
        psu = request.form['psu']
        case = request.form['case']
        cooling_system = request.form['cooling_system']
        operating_system = request.form['operating_system']
        additional_info = request.form['additional_info']

        cursor.execute("INSERT INTO pc_specifications (pc_id, cpu, gpu, ram, storage, motherboard, psu, case, cooling_system, operating_system, additional_info) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", 
                       (pc_id, cpu, gpu, ram, storage, motherboard, psu, case, cooling_system, operating_system, additional_info))
        connection.commit()

    cursor.execute("SELECT * FROM pc_specifications WHERE pc_id = %s", (pc_id,))
    specs = cursor.fetchall()

    cursor.close()
    connection.close()
    return render_template('pc_specifications.html', specs=specs, pc_id=pc_id)

#game performances
@app.route('/game-performance/<pc_id>', methods=['GET', 'POST'])
def game_performance(pc_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if request.method == 'POST':
        game_name = request.form['game_name']
        fps_1080p = request.form['fps_1080p']
        fps_1440p = request.form['fps_1440p']
        fps_4k = request.form['fps_4k']
        settings_preset = request.form['settings_preset']
        benchmark_details = request.form['benchmark_details']

        cursor.execute("INSERT INTO game_performance (pc_id, game_name, fps_1080p, fps_1440p, fps_4k, settings_preset, benchmark_details) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
                       (pc_id, game_name, fps_1080p, fps_1440p, fps_4k, settings_preset, benchmark_details))
        connection.commit()

    cursor.execute("SELECT * FROM game_performance WHERE pc_id = %s", (pc_id,))
    performances = cursor.fetchall()

    cursor.close()
    connection.close()
    return render_template('game_performance.html', performances=performances, pc_id=pc_id)

#pc images
@app.route('/pc-images/<pc_id>', methods=['GET', 'POST'])
def pc_images(pc_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if request.method == 'POST':
        image_url = request.form['image_url']
        is_primary = request.form['is_primary']
        verification_image = request.form['verification_image']

        cursor.execute("INSERT INTO pc_images (pc_id, image_url, is_primary, verification_image) VALUES (%s, %s, %s, %s)", 
                       (pc_id, image_url, is_primary, verification_image))
        connection.commit()

    cursor.execute("SELECT * FROM pc_images WHERE pc_id = %s", (pc_id,))
    images = cursor.fetchall()

    cursor.close()
    connection.close()
    return render_template('pc_images.html', images=images, pc_id=pc_id)

#parts
@app.route('/parts', methods=['GET', 'POST'])
def parts():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if request.method == 'POST':
        seller_id = request.form['seller_id']
        category = request.form['category']
        brand = request.form['brand']
        model = request.form['model']
        condition = request.form['condition']
        price = request.form['price']
        warranty_status = request.form['warranty_status']
        warranty_remaining = request.form['warranty_remaining']
        verification_status = request.form['verification_status']
        selling_status = request.form['selling_status']

        cursor.execute("INSERT INTO parts (seller_id, category, brand, model, condition, price, warranty_status, warranty_remaining, verification_status, selling_status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", 
                       (seller_id, category, brand, model, condition, price, warranty_status, warranty_remaining, verification_status, selling_status))
        connection.commit()

    cursor.execute("SELECT * FROM parts")
    parts = cursor.fetchall()

    cursor.close()
    connection.close()
    return render_template('parts.html', parts=parts)

@app.route('/parts/add_parts', methods=['GET', 'POST'])
def add_parts():
    if request.method == 'POST':
        # Get the part details from the form
        part_name = request.form.get('name')
        part_description = request.form.get('description')
        part_price = request.form.get('price')
        
        # Add the new part to the in-memory list
        new_part = {
            'id': len(parts) + 1,
            'name': part_name,
            'description': part_description,
            'price': part_price
        }
        parts.append(new_part)
        
        # Redirect to a different page or show a success message
        return redirect(url_for('view_parts'))

    return render_template('add_parts.html')

# Route to view all parts (just for demonstration)
@app.route('/parts/view_parts')
def view_parts():
    return render_template('view_parts.html', parts=parts)

#wishlist
@app.route('/wishlist', methods=['GET', 'POST'])
def wishlist():
    if 'user_id' not in session:
        flash('You must be logged in to view your wishlist.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    page = request.args.get('page', 1, type=int)  # Get page from the query string, default to 1
    limit = request.args.get('limit', 5, type=int)  # Default items per page to 5
    sort_by = request.args.get('sort', 'name_asc')  # Default sort by name ascending

    # Connection to the database and fetching wishlist items
    connection = get_db_connection()
    wishlist_items = []
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT p.product_id, p.name, p.description, p.price, p.image_url
                FROM wishlist w
                JOIN products p ON w.product_id = p.product_id
                WHERE w.user_id = %s
                ORDER BY p.name ASC
                LIMIT %s OFFSET %s
            """, (user_id, limit, (page - 1) * limit))  # Pagination logic with OFFSET
            wishlist_items = cursor.fetchall()

            # You can implement sorting logic here if needed
        except Exception as e:
            print(f"Error fetching wishlist: {e}")
            flash('Failed to retrieve wishlist.', 'danger')
        finally:
            cursor.close()
            connection.close()

    return render_template('wishlist.html', wishlist_items=wishlist_items, page=page, limit=limit, sort_by=sort_by)

@app.route('/add_to_wishlist/<int:product_id>', methods=['POST'])
def add_to_wishlist(product_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'You must be logged in to add items to your wishlist.'}), 400

    csrf_token = request.headers.get('X-CSRFToken')
    if not csrf_token or csrf_token != session.get('_csrf_token'):
        return jsonify({'success': False, 'message': 'Invalid CSRF token.'}), 400

    user_id = session['user_id']
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT * FROM wishlist WHERE user_id = %s AND product_id = %s", (user_id, product_id))
            if cursor.fetchone():
                return jsonify({'success': False, 'message': 'Product is already in your wishlist.'}), 400
            cursor.execute("INSERT INTO wishlist (user_id, product_id) VALUES (%s, %s)", (user_id, product_id))
            connection.commit()
            return jsonify({'success': True, 'message': 'Product added to wishlist!'})
        except Exception as e:
            print(f"Error adding to wishlist: {e}")
            return jsonify({'success': False, 'message': 'Failed to add product to wishlist.'}), 500
        finally:
            cursor.close()
            connection.close()
    return jsonify({'success': False, 'message': 'Database connection error.'}), 500


@app.route('/remove_from_wishlist/<int:product_id>', methods=['POST'])
def remove_from_wishlist(product_id):
    if 'user_id' not in session:
        flash('You must be logged in to manage your wishlist.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                "DELETE FROM wishlist WHERE user_id = %s AND product_id = %s",
                (user_id, product_id)
            )
            connection.commit()
            flash('Product removed from wishlist.', 'success')
        except Exception as e:
            print(f"Error removing from wishlist: {e}")
            flash('Failed to remove product from wishlist.', 'danger')
        finally:
            cursor.close()
            connection.close()
    return redirect(url_for('wishlist'))

#notifications
@app.route('/notifications', methods=['GET'])
def notifications():
    # Simulating fetching notifications for a logged-in user
    if 'user_id' not in session:
        return jsonify({'notifications': []})  # No notifications if not logged in

    user_id = session['user_id']
    notifications = [
        {
            'message': 'Your order #1234 has been shipped!',
            'timestamp': '2024-11-20 10:00 AM'
        },
        {
            'message': 'New gaming PC is available now!',
            'timestamp': '2024-11-19 5:30 PM'
        }
    ]  # Replace with actual database query to fetch user notifications

    return jsonify({'notifications': notifications})


@app.route('/searchbar')
def searchbar():
    return render_template('searchbar.html')

if __name__ == '__main__':
    app.run(debug=True)
