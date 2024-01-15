from flask import Flask, render_template, request, redirect, url_for, flash
import mysql.connector
from flask import send_from_directory
from werkzeug.utils import secure_filename
import os

#AES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import datetime

#Session
from flask import session
from flask import Flask, render_template, request, redirect, url_for, flash, session, get_flashed_messages
from datetime import timedelta

#RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key


# Version Checked!

app = Flask(__name__)
app.secret_key = 'your_secret_key' 

# Set the session lifetime to 7 days
app.permanent_session_lifetime = timedelta(days=7)

#RSA
# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Get the public key
public_key = private_key.public_key()

# Function to read credentials from file
def read_credentials(filename='credentials.txt'):
    credentials = {}
    with open(filename, 'r') as file:
        for line in file:
            key, value = line.strip().split(': ')
            credentials[key] = value
    return credentials

# MySQL Configuration (Update with your database credentials)
# Function to create a MySQL connection
def create_db_connection():
    credentials = read_credentials()
    connection = mysql.connector.connect(
        host=credentials['host'],
        user=credentials['user'],
        password=credentials['password'],
        database=credentials['database']
    )
    return connection

# MySQL Configuration
conn = create_db_connection()
cursor = conn.cursor()

# Upload File
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt'}
UserEmail = "Sandesh"

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the "uploads" folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Function
def fetch_user_by_email(email):
    query = "SELECT UserID FROM users WHERE email = %s"
    cursor.execute(query, (email,))
    user = cursor.fetchone()
    return user

# Function to create the users table if it doesn't exist
def create_users_table():
    query = """
    CREATE TABLE IF NOT EXISTS users (
        UserID INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('Admin', 'Editor', 'Reader', 'Viewer') NOT NULL
    )
    """
    cursor.execute(query)
    conn.commit()

create_users_table()

#def to create EncryptionData Table
def create_encryption_data_table():
    query = """
    CREATE TABLE IF NOT EXISTS EncryptionData (
        ID INT AUTO_INCREMENT PRIMARY KEY,
        UserID INT,
        EmailID VARCHAR(255),
        AESCipher BLOB,
        AESKey VARCHAR(255),
        RSACipher VARBINARY(2048),  -- Change to a larger size if needed
        RSAPublicKey TEXT,
        RSAPrivateKey TEXT,
        DateStored TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (UserID) REFERENCES users(UserID)
    )
    """
    cursor.execute(query)
    conn.commit()


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        Email = request.form['email']
        password = request.form['password']
        print("Login: "+ Email)

        # Check if the provided credentials are valid
        query = "SELECT * FROM users WHERE email=%s AND password=%s"
        cursor.execute(query, (Email, password))
        user = cursor.fetchone()

        if user:
            # Set session variables or use a more secure method for user authentication
            session['email'] = Email  # Set the user's email in the session
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        # Insert the new user into the database without providing UserID
        query = "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (name, email, password, role))
        conn.commit()

        flash('Registered successfully! Redirecting to login page in 3 seconds.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    # Add authentication check for accessing the dashboard
    # For simplicity, this route is accessible without proper authentication in this example
    email = session.get('email')
    print("Dashboard: "+ email)

    if not email:
        flash('User not logged in.', 'danger')
        return redirect(url_for('login'))

    # Fetch entries from EncryptionData table for the logged-in user
    query = "SELECT ID, DateStored, AESCipher, RSACipher, RSAPublicKey FROM EncryptionData WHERE EmailID = %s"
    cursor.execute(query, (email,))
    entries = cursor.fetchall()

    # Fetch user's name
    query_name = "SELECT name FROM users WHERE email = %s"
    cursor.execute(query_name, (email,))
    user_name = cursor.fetchone()[0]  # Assuming the email is unique
    print(user_name)

    return render_template('dashboard.html', name=user_name, entries=entries)

@app.route('/delete/<int:entry_id>', methods=['POST'])
def delete_entry(entry_id):
    # Delete the entry from the database
    query_delete = "DELETE FROM EncryptionData WHERE ID = %s"
    cursor.execute(query_delete, (entry_id,))
    conn.commit()

    flash('Entry deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        # Retrieve the current user's UserID and EmailID from the session
        email = session.get('email')
        print("Encrypt: "+ email)

        if not email:
            flash('User not logged in.', 'danger')
            return redirect(url_for('login'))
        
        query = "SELECT UserID FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        userid = cursor.fetchone()[0]

        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['file']

        # Check if the file is empty
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        # Check if the file extension is allowed
        if file and allowed_file(file.filename):
            # Generate a unique AES key for each file
            aes_key = os.urandom(16)
            cipher = AES.new(aes_key, AES.MODE_CBC)

            # Convert AES key to string for RSA encryption
            aes_key_str = base64.urlsafe_b64encode(aes_key).decode('utf-8')

            # Encrypt the AES key with RSA
            rsa_cipher = public_key.encrypt(
                aes_key_str.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Convert RSA public and private keys to strings for storage
            rsa_public_key_str = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            rsa_private_key_str = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            # Read the content of the file
            file_content = file.read()
            padded_content = pad(file_content, AES.block_size)

            # Encrypt the file content
            aes_cipher = cipher.encrypt(padded_content)

            # Store the encrypted data in the database
            query = """
                INSERT INTO EncryptionData (UserID, EmailID, AESCipher, AESKey, RSACipher, RSAPublicKey, RSAPrivateKey) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (userid, email, aes_cipher, aes_key_str, rsa_cipher, rsa_public_key_str, rsa_private_key_str))
            conn.commit()

            flash('File encrypted and stored successfully!', 'success')
            return redirect(url_for('dashboard'))

        else:
            flash('Invalid file type. Please upload a .txt file.', 'danger')

    return render_template('encrypt.html', messages=get_flashed_messages())

@app.route('/decrypt/<int:entry_id>', methods=['GET'])
def decrypt(entry_id):
    # Fetch the AESCipher, AESKey, and RSAPrivateKey from the database
    query = "SELECT AESCipher, AESKey, RSACipher, RSAPrivateKey FROM EncryptionData WHERE ID = %s"
    cursor.execute(query, (entry_id,))
    result = cursor.fetchone()

    if result:
        aes_cipher = result[0]
        aes_key_str = result[1]
        rsa_cipher = result[2]
        rsa_private_key_str = result[3]

        # Load the RSA private key from the string
        rsa_private_key = load_pem_private_key(
            rsa_private_key_str.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        # Ensure the length of aes_key_str is a multiple of 4
        padding_length = len(aes_key_str) % 4
        if padding_length > 0:
            aes_key_str += '=' * (4 - padding_length)

        # Decode the AES key from the base64-encoded string
        aes_key = base64.urlsafe_b64decode(aes_key_str)

        # Decrypt the AES cipher with the obtained AES key
        cipher = AES.new(aes_key, AES.MODE_CBC)
        decrypted_data = unpad(cipher.decrypt(aes_cipher), AES.block_size)

        try:
            # Attempt to decode as UTF-8
            plaintext = decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            # If decoding as UTF-8 fails, display the data in a different way or handle the error
            plaintext = decrypted_data.decode(errors='replace')  # Use 'replace' to replace invalid characters with the Unicode replacement character

        return render_template('decrypt.html', plaintext=plaintext)

    else:
        flash('Entry not found.', 'danger')
        return redirect(url_for('dashboard'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


if __name__ == '__main__':
    create_users_table()
    create_encryption_data_table()  # Add this line to create the EncryptionData table
    app.run(debug=True)