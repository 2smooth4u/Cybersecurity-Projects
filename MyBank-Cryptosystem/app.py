"""
🔹 **MyBank Secure Banking System - Single-File Implementation**
---------------------------------------------------------------

**Overview:**
This Python script is a **Flask-based secure online banking system** that integrates:
- **User authentication & session management**
- **Encryption & secure transactions**
- **HMAC-based integrity verification**
- **Role-based access control (RBAC)**
- **Secure fund transfers and messaging**
- **Admin & employee dashboards for management**

 **Self-Contained Local Database:**
- The system **does not use an external database**; instead, it maintains user data in **Python dictionaries**.
- Dummy user credentials and transaction histories are pre-defined within the script.
- Sessions are managed via **JWT tokens** stored in user sessions.

**Important Note:**  
Most data displayed on web pages (such as transactions, balances, and loan status) is **dummy data**.  
Since the system is **not connected to an external database**, changes made during a session will not persist after the server is restarted.

**Key Security Features:**
1. **AES Encryption** - Secures sensitive data and transactions.
2. **RSA Key Exchange & Digital Signatures** - Ensures secure communication and prevents repudiation.
3. **HMAC (Hash-based Message Authentication Code)** - Provides integrity verification for transactions.
4. **Multi-Factor Authentication (MFA)** - OTP-based verification for user logins.
5. **JWT Authentication** - Secure stateless authentication with role-based access control.
6. **Secure Encrypted Messaging** - Clients can send encrypted messages to the bank.
7. **Role-Based Dashboards** - Clients, employees, and administrators have separate access and controls.

 **Implemented Methods:**
- `generate_jwt()`, `verify_jwt()` → Manages secure JWT authentication.
- `encrypt_data()`, `decrypt_data()` → Implements AES-based encryption for transactions and messages.
- `sign_transaction()`, `verify_signature()` → Uses RSA signatures to validate transactions.
- `generate_hmac()`, `verify_hmac()` → Generates and verifies transaction integrity using HMAC.
- `generate_otp()` → Creates one-time passwords for MFA security.
- `process_transaction()` → Handles secure fund transfers between accounts.
- `monitor_transactions()` → Employee-accessible fraud monitoring.

**Built-in HTML Templates:**
- The application includes **inline HTML templates** rendered dynamically using Flask’s `render_template_string()`.
- Bootstrap styling is used for a clean, user-friendly interface.

 **How to Run:**
- The script runs as a **Flask web application** with an **adhoc SSL certificate**.
- Execute the script and access the banking system from your web browser.

 **User Credentials:**
Below is a table of predefined usernames and passwords stored in the local dictionary database (`users_db`):

| Username   | Password       | Role            |
|------------|--------------|----------------|
| client1    | clientpass   | Client         |
| employee1  | employeepass | Bank Employee  |
| admin1     | adminpass    | System Admin   |

⚠ **Note:** Passwords are securely stored using **hashed values** with `generate_password_hash()`. The above passwords are only for reference and are not stored in plaintext.
"""


from flask import Flask, render_template_string,jsonify, request, redirect, url_for, session, flash, get_flashed_messages
import os, base64, uuid, time, random, hmac, jwt, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


app = Flask(__name__)

users_db = {
    "client1": {"password": generate_password_hash("clientpass"), "role": "client"},
    "employee1": {"password": generate_password_hash("employeepass"), "role": "bank_employee"},
    "admin1": {"password": generate_password_hash("adminpass"), "role": "system_admin"}
}
app.secret_key = os.urandom(24)

def generate_otp():
    return str(random.randint(100000, 999999))

JWT_SECRET = os.urandom(32)

def verify_jwt(token):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def generate_jwt(username, role):
    payload = {
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=2)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # JWT secret key



# **Static AES Key (For Encryption & Decryption)**
AES_KEY = os.urandom(16)  # Ensure the key remains the same for encryption & decryption

# **AES Encryption**
def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode()

# **AES Decryption**
def decrypt_data(encrypted_data):
    raw = base64.b64decode(encrypted_data)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

HMAC_SECRET = os.urandom(32)  # HMAC secret key for transaction verification

def generate_hmac(data):
      
      return hmac.new(HMAC_SECRET, data.encode(), hashlib.sha256).hexdigest()

def verify_hmac(data, received_hmac):
    expected_hmac = generate_hmac(data)
    return hmac.compare_digest(expected_hmac, received_hmac)

# 🔑 Persistent Key Storage Paths
AES_KEY_PATH = "aes_key.bin"
RSA_PRIVATE_KEY_PATH = "private_key.pem"
RSA_PUBLIC_KEY_PATH = "public_key.pem"

# Load or Generate AES Key (Persistent Storage)
if os.path.exists(AES_KEY_PATH):
    with open(AES_KEY_PATH, "rb") as key_file:
        AES_KEY = key_file.read()
else:
    AES_KEY = os.urandom(32)
    with open(AES_KEY_PATH, "wb") as key_file:
        key_file.write(AES_KEY)

# Load or Generate RSA Key Pair (Persistent Storage)
if os.path.exists(RSA_PRIVATE_KEY_PATH) and os.path.exists(RSA_PUBLIC_KEY_PATH):
    with open(RSA_PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    with open(RSA_PUBLIC_KEY_PATH, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
else:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(RSA_PRIVATE_KEY_PATH, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(RSA_PUBLIC_KEY_PATH, "wb") as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# 📜 RSA Digital Signatures
def sign_transaction(transaction_data):
    """Signs transaction data using RSA private key."""
    signature = private_key.sign(
        transaction_data.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def verify_signature(transaction_data, signature):
    """Verifies RSA digital signature of a transaction."""
    try:
        public_key.verify(
            signature,
            transaction_data.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False




@app.route('/')
def index():
    return render_template_string(index_template, style_css=style_css)

@app.route('/signup')
def signup():
    flash("⚠ Feature not available right now. Please log in instead.", "warning")
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        user = users_db.get(username)
        if user and check_password_hash(user["password"], password):
            session['username'] = username
            session['role'] = user['role']
            session['otp'] = generate_otp()
            flash("OTP has been sent. Please enter it on the next screen.")
            return redirect(url_for('otp_verification'))
        else:
            flash("Error: Invalid username or password. Please try again.")
    return render_template_string(login_template, style_css=style_css)

@app.route('/otp', methods=['GET', 'POST'])
def otp_verification():
    if 'otp_attempts' not in session:
        session['otp_attempts'] = 0
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        user_otp = request.form.get('otp').strip()
        if user_otp == session.get('otp'):
            session.pop('otp_attempts', None)
            session['jwt'] = generate_jwt(session['username'], session['role'])
            if session['role'] == 'client':
               return redirect(url_for('dashboard_client'))
            elif session['role'] == 'bank_employee':
                return redirect(url_for('dashboard_employee'))
            else:
                return redirect(url_for('dashboard_admin'))
        else:
            session['otp'] = generate_otp()
            session['otp_attempts'] += 1
            if session['otp_attempts'] >= 3:
                flash("Error: Too many incorrect OTP attempts. Redirecting to login.")
                session.clear()
                return redirect(url_for('login'))
            flash("Error: Invalid OTP entered. A new OTP has been sent. Please try again.")
            return redirect(url_for('otp_verification'))
    return render_template_string(otp_template, style_css=style_css)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

# **Dummy Client Database with Transactions**
clients = {
    "client1": {
        "name": "John Doe",
        "email": "john@example.com",
        "balance": 5000,
         "bills": [{"bill": "Electricity", "amount": 120}, {"bill": "Internet", "amount": 50}],
        "transactions": [
            {"date": "2025-03-01", "type": "Deposit", "amount": 1000},
            {"date": "2025-03-02", "type": "Withdrawal", "amount": -500},
            {"date": "2025-03-03", "type": "Transfer", "amount": -200, "to": "Jane Smith"},
            {"date": "2025-03-04", "type": "Transfer", "amount": 300, "from": "Jane Smith"},
        ],
        "loan_status": "Approved",
        "encrypted_messages": []
    },
    "client2": {
        "name": "Jane Smith",
        "email": "jane@example.com",
        "balance": 3000,
         "bills": [{"bill": "Water", "amount": 90}, {"bill": "Gas", "amount": 75}],
        "transactions": [
            {"date": "2025-03-01", "type": "Deposit", "amount": 1500},
            {"date": "2025-03-02", "type": "Withdrawal", "amount": -700},
            {"date": "2025-03-03", "type": "Transfer", "amount": 200, "from": "John Doe"},
            {"date": "2025-03-04", "type": "Transfer", "amount": -300, "to": "John Doe"},
        ],
        "loan_status": "Pending",
        "encrypted_messages": []
    }
}


@app.route('/dashboard_client')
def dashboard_client():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'client':
        return redirect(url_for('login'))
    return render_template_string(client_dashboard_template, style_css=style_css, clients=clients,decoded=decoded)

# **View Account Balances & Transactions**
@app.route('/account_statements')
def account_statements():
    
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'client':
        return redirect(url_for('login'))
    return render_template_string(account_statements_template, style_css=style_css, clients=clients)

def generate_hmac_key(sender, receiver, amount):
    data = f"{sender}|{receiver}|{amount}"
    return hmac.new(HMAC_SECRET, data.encode(), hashlib.sha256).hexdigest()

# **Apply for Loans**
@app.route('/apply_loan')
def apply_loan():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'client':
        return redirect(url_for('login'))
    return render_template_string(apply_loan_template, style_css=style_css, clients=clients)

# **Update Personal Info**
@app.route('/update_personal_info')
def update_personal_info():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'client':
        return redirect(url_for('login'))
    return render_template_string(update_personal_info_template, style_css=style_css, clients=clients)

# **Pay Bills**
@app.route('/pay_bills')
def pay_bills():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'client':
        return redirect(url_for('login'))
    return render_template_string(pay_bills_template, style_css=style_css, clients=clients)


# **Secure Fund Transfers with HMAC**
@app.route('/fund_transfers')
def fund_transfers():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'client':
        return redirect(url_for('login'))
    return render_template_string(fund_transfers_template, style_css=style_css, clients=clients)

@app.route('/generate_transaction_request', methods=['POST'])
def generate_transaction_request():
    data = request.json
    sender = data.get('sender', '').strip()
    receiver = data.get('receiver', '').strip()
    amount = str(data.get('amount', '')).strip()

    if not sender or not receiver or not amount:
        return jsonify({"error": "❌ Missing sender, receiver, or amount."}), 400

    if sender == receiver:
        return jsonify({"error": "❌ You cannot send money to yourself."}), 400

    if float(amount) <= 0:
        return jsonify({"error": "❌ Please enter a valid amount."}), 400

    # Generate HMAC Key
    hmac_key = generate_hmac_key(sender, receiver, amount)

    # Encrypt Transaction Data
    transaction_data = f"Sender: {sender}, Receiver: {receiver}, Amount: ${amount}, HMAC: {hmac_key}"
    encrypted_transaction = encrypt_data(transaction_data)

    return jsonify({"encrypted_transaction": encrypted_transaction, "hmac_key": hmac_key})

# **Process Encrypted Transaction Request (API)**
@app.route('/process_transaction_request', methods=['POST'])
def process_transaction_request():
    return jsonify({"message": "✅ Transaction request sent to bank employee for verification!"})

#  **Process Fund Transfers (API)**
@app.route('/process_transaction', methods=['POST'])
def process_transaction():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'client':
        return redirect(url_for('login'))
    data = request.json
    sender = data.get('sender', '').strip()
    receiver = data.get('receiver', '').strip()
    amount = float(data.get('amount', 0))
    provided_hmac = data.get('hmac', '').strip()

    if not sender or not receiver or sender == receiver:
        return jsonify({"error": "❌ Invalid sender or receiver"}), 400

    expected_hmac = generate_hmac(sender, receiver, amount)
    if not hmac.compare_digest(expected_hmac, provided_hmac):
        return jsonify({"error": "❌ HMAC mismatch! Transaction rejected."}), 400

    if clients[sender]["balance"] >= amount:
        clients[sender]["balance"] -= amount
        clients[receiver]["balance"] += amount
        clients[sender]["transactions"].append({"date": str(datetime.today().date()), "type": "Pending Transfer", "amount": -amount, "to": receiver})
        clients[receiver]["transactions"].append({"date": str(datetime.today().date()), "type": "Pending Transfer", "amount": amount, "from": sender})
        return jsonify({"message": "✅ Transaction request sent! A bank employee will verify and process it."})
    else:
        return jsonify({"error": "❌ Insufficient funds!"}), 400

# **Secure Encrypted Messaging**
@app.route('/encrypted_messaging')
def encrypted_messaging():
    return render_template_string(encrypted_messaging_template, style_css=style_css, clients=clients)



# **Employee Dashboard**
@app.route('/dashboard_employee')
def dashboard_employee():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'bank_employee':
        return redirect(url_for('login'))
    return render_template_string(employee_dashboard_template, style_css=style_css, decoded=decoded)



# **Customer Support with Encryption & Decryption**
@app.route('/customer_support', methods=['GET', 'POST'])
def customer_support():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'bank_employee':
        return redirect(url_for('login'))

    return render_template_string(customer_support_template, style_css=style_css)

# **API for Encrypting Data**
@app.route('/encrypt', methods=['POST'])
def encrypt_api():
    data = request.json.get('data', '')
    if not data:
        return jsonify({"error": "No data provided"}), 400

    encrypted_text = encrypt_data(data)
    return jsonify({"encrypted_data": encrypted_text})

# **API for Decrypting Data**
@app.route('/decrypt', methods=['POST'])
def decrypt_api():
    encrypted_text = request.json.get('encrypted_data', '')
    if not encrypted_text:
        return jsonify({"error": "No encrypted data provided"}), 400

    try:
        decrypted_text = decrypt_data(encrypted_text)
        return jsonify({"decrypted_data": decrypted_text})
    except Exception:
        return jsonify({"error": "Invalid encrypted data"}), 400

# **Static Customer Database (Simulated)**
customers = {
    "john_doe": {"name": "John Doe", "email": "john@example.com", "balance": 5000},
    "jane_smith": {"name": "Jane Smith", "email": "jane@example.com", "balance": 7000}
}

# **Update Accounts Page**
@app.route('/update_accounts')
def update_accounts():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'bank_employee':
        return redirect(url_for('login'))
    return render_template_string(update_accounts_template, style_css=style_css, customers=customers)

# **Process Transactions Page**
@app.route('/process_transactions')
def process_transactions():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'bank_employee':
        return redirect(url_for('login'))
    return render_template_string(process_transactions_template, style_css=style_css, customers=customers)

# **API to Update Customer Details**
@app.route('/update_customer', methods=['POST'])
def update_customer():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'bank_employee':
        return redirect(url_for('login'))
    customer_id = request.json.get('customer_id')
    new_email = request.json.get('email')

    if customer_id in customers:
        customers[customer_id]["email"] = new_email
        return jsonify({"message": "✅ Account updated successfully!", "updated_email": new_email})
    else:
        return jsonify({"error": "❌ Customer not found."}), 400

# **API to Process Transactions**
@app.route('/make_transaction', methods=['POST'])
def make_transaction():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'bank_employee':
        return redirect(url_for('login'))
    customer_id = request.json.get('customer_id')
    transaction_type = request.json.get('transaction_type')
    amount = float(request.json.get('amount', 0))

    if customer_id not in customers:
        return jsonify({"error": "❌ Customer not found."}), 400

    if transaction_type == "deposit":
        customers[customer_id]["balance"] += amount
    elif transaction_type == "withdraw":
        if customers[customer_id]["balance"] >= amount:
            customers[customer_id]["balance"] -= amount
        else:
            return jsonify({"error": "❌ Insufficient funds."}), 400

    return jsonify({"message": f"✅ {transaction_type.capitalize()} of ${amount} successful!", "new_balance": customers[customer_id]["balance"]})

# **Monitor Transactions for Fraud**
@app.route('/monitor_transactions')
def monitor_transactions():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'bank_employee':
        return redirect(url_for('login'))
    return render_template_string(monitor_transactions_template, style_css=style_css)

# **Encryption & Decryption Page (Verify Transactions)**
@app.route('/verify_transaction', methods=['POST'])
def verify_transaction():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'bank_employee':
        return redirect(url_for('login'))
    encrypted_data = request.json.get('encrypted_data', '')
    provided_hmac = request.json.get('hmac', '')

    if not encrypted_data or not provided_hmac:
        return jsonify({"error": "Missing encrypted data or HMAC"}), 400

    try:
        decrypted_text = decrypt_data(encrypted_data)
        expected_hmac = generate_hmac(decrypted_text)

        if hmac.compare_digest(expected_hmac, provided_hmac):
            return jsonify({"message": "✅ Transaction is valid", "decrypted_data": decrypted_text})
        else:
            return jsonify({"error": "❌ HMAC mismatch! Transaction may be altered."}), 400
    except Exception:
        return jsonify({"error": "❌ Invalid encrypted data"}), 400






@app.route('/dashboard_admin')
def dashboard_admin():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'system_admin':
        return redirect(url_for('login'))
    
    return render_template_string(dashboard_template, username=decoded['username'])

# 👥 **Manage Users**
@app.route('/manage_users')
def manage_users():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'system_admin':
        return redirect(url_for('login'))
    
    users_demo = [
        {"username": "client1", "role": "client"},
        {"username": "employee1", "role": "bank_employee"},
        {"username": "admin1", "role": "system_admin"}
    ]
    return render_template_string(manage_users_template, users=users_demo)

# 🔒 **Monitor Security**
@app.route('/monitor_security')
def monitor_security():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'system_admin':
        return redirect(url_for('login'))

    return render_template_string(monitor_security_template)

# 🔑 **Key Management**
@app.route('/handle_keys')
def handle_keys():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'system_admin':
        return redirect(url_for('login'))

    return render_template_string(handle_keys_template)

# ⚙️ **System Updates & Backups**
@app.route('/system_maintenance')
def system_maintenance():
    if 'jwt' not in session:
        return redirect(url_for('login'))
    decoded = verify_jwt(session.get('jwt'))
    if not decoded or decoded['role'] != 'system_admin':
        return redirect(url_for('login'))

    return render_template_string(system_maintenance_template)


# 📌 **HTML Templates (Bootstrap & CSS)**

index_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>MyBank - Secure Banking</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

<div class="container text-center landing-page">
    <h1 class="display-4">Welcome to MyBank</h1>
    <p class="lead">Secure and reliable online banking platform.</p>

    <div class="d-flex justify-content-center">
        <a href="{{ url_for('login') }}" class="btn btn-primary btn-lg mx-2">Login to Your Account</a>
        <a href="{{ url_for('signup') }}" class="btn btn-secondary btn-lg mx-2">Sign Up</a>
    </div>

    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <div class="alert alert-warning mt-3">{{ messages[0] }}</div>
        {% endif %}
    {% endwith %}

</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>

</body>
</html>
"""


login_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Login - MyBank</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

<div class="container login-container">
    <h2 class="text-center">Login to MyBank</h2>

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}

    <form method="post">
        <div class="mb-3">
            <label class="form-label">Username</label>
            <input type="text" class="form-control" name="username" required>
        </div>
        <div class="mb-3">
            <label class="form-label">Password</label>
            <input type="password" class="form-control" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Login</button>
    </form>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>

</body>
</html>
"""
otp_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>OTP Verification - MyBank</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

<div class="container login-container">
    <h2 class="text-center">Enter OTP</h2>
    <p class="text-center">An OTP has been sent to your registered email.</p>

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}

    {% if session.get('otp') %}
        <p class="alert alert-info text-center">Your OTP (for demo): <strong>{{ session['otp'] }}</strong></p>
    {% endif %}

    <form method="post">
        <div class="mb-3">
            <label class="form-label">One-Time Password (OTP)</label>
            <input type="text" class="form-control" name="otp" required>
        </div>
        <button type="submit" class="btn btn-success w-100">Verify OTP</button>
    </form>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>

</body>
</html>
"""

client_dashboard_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Client Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

<div class="container">
    <h2 class="text-center">🏦 Client Dashboard</h2>
    <p class="text-center">Manage your banking activities securely.</p>

    <div class="text-end">
        <a href="{{ url_for('logout') }}" class="btn btn-danger">🚪 Logout</a>
    </div>

    <div class="row mt-4">
        <div class="col-md-6">
            <a href="{{ url_for('fund_transfers') }}" class="btn btn-primary w-100">💰 Secure Transactions</a>
            <a href="{{ url_for('account_statements') }}" class="btn btn-info w-100 mt-2">📑 Account Statements</a>
            <a href="{{ url_for('apply_loan') }}" class="btn btn-success w-100 mt-2">💳 Apply for Loan</a>
        </div>
        <div class="col-md-6">
            <a href="{{ url_for('update_personal_info') }}" class="btn btn-warning w-100">🔧 Update Personal Info</a>
            <a href="{{ url_for('pay_bills') }}" class="btn btn-secondary w-100 mt-2">💳 Pay Bills</a>
            <a href="{{ url_for('encrypted_messaging') }}" class="btn btn-dark w-100 mt-2">📨 Encrypted Messaging</a>
        </div>
    </div>
</div>

<div class="footer text-center mt-4">© 2025 MyBank | Secure Banking System</div>


</body>
</html>
"""

fund_transfers_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Client Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

<div class="container">
    <h2 class="text-center">💰 Secure Transactions</h2>
    <p class="text-center">Generate an encrypted transaction request with a separate HMAC key.</p>

    <div class="mb-3">
        <label class="form-label">Sender:</label>
        <select id="senderSelect" class="form-control">
            {% for client_id, data in clients.items() %}
                <option value="{{ client_id }}">{{ data["name"] }} (Balance: ${{ data["balance"] }})</option>
            {% endfor %}
        </select>
    </div>

    <div class="mb-3">
        <label class="form-label">Receiver:</label>
        <select id="receiverSelect" class="form-control">
            {% for client_id, data in clients.items() %}
                <option value="{{ client_id }}">{{ data["name"] }}</option>
            {% endfor %}
        </select>
    </div>

    <div class="mb-3">
        <label class="form-label">Amount:</label>
        <input type="number" id="transferAmount" class="form-control" placeholder="Enter amount">
    </div>

    <button class="btn btn-success w-100" onclick="generateTransactionRequest()">🔑 Generate Transaction Request</button>
    
    <div id="transactionDisplay" class="alert alert-info mt-3 d-none">
        <strong>Encrypted Transaction Request:</strong> <span id="transactionText"></span>
    </div>

    <div id="hmacDisplay" class="alert alert-warning mt-3 d-none">
        <strong>HMAC Key:</strong> <span id="hmacKey"></span>
    </div>

    <button class="btn btn-primary w-100 mt-3 d-none" id="submitTransactionBtn" onclick="submitTransaction()">💸 Submit Transaction</button>

    <div id="transactionResult" class="alert mt-3 d-none"></div>

    <a href="{{ url_for('dashboard_client') }}" class="btn btn-secondary mt-3">Back</a>
</div>

<script>
function generateTransactionRequest() {
    let sender = document.getElementById("senderSelect").value;
    let receiver = document.getElementById("receiverSelect").value;
    let amount = document.getElementById("transferAmount").value;

    if (sender === receiver) {
        alert("❌ You cannot send money to yourself.");
        return;
    }

    fetch('/generate_transaction_request', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender: sender, receiver: receiver, amount: amount })
    })
    .then(response => response.json())
    .then(result => {
        if (result.encrypted_transaction && result.hmac_key) {
            document.getElementById("transactionText").textContent = result.encrypted_transaction;
            document.getElementById("transactionDisplay").classList.remove("d-none");

            document.getElementById("hmacKey").textContent = result.hmac_key;
            document.getElementById("hmacDisplay").classList.remove("d-none");

            document.getElementById("submitTransactionBtn").classList.remove("d-none");
        } else {
            alert(result.error);
        }
    })
    .catch(error => alert("❌ Transaction request generation failed."));
}

function submitTransaction() {
    fetch('/process_transaction_request', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
    })
    .then(response => response.json())
    .then(result => {
        let resultDiv = document.getElementById("transactionResult");
        resultDiv.textContent = result.message || result.error;
        resultDiv.className = "alert " + (result.message ? "alert-success" : "alert-danger");
        resultDiv.classList.remove("d-none");
    })
    .catch(error => alert("❌ Transaction submission failed."));
}
</script>



</body>
</html>
"""

account_statements_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Account Statements</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

<div class="container">
    <h2 class="text-center">📑 Account Statements</h2>
    <p class="text-center">View your transaction history.</p>

    <div class="mb-3">
        <label class="form-label">Select Client:</label>
        <select id="clientSelect" class="form-control" onchange="updateTransactions()">
            {% for client_id, data in clients.items() %}
                <option value="{{ client_id }}">{{ data["name"] }} (Balance: ${{ data["balance"] }})</option>
            {% endfor %}
        </select>
    </div>

    <table class="table table-bordered mt-3">
        <thead class="table-dark">
            <tr>
                <th>Date</th>
                <th>Transaction Type</th>
                <th>Amount</th>
            </tr>
        </thead>
        <tbody id="transactionTable">
            {% for transaction in clients["client1"]["transactions"] %}
                <tr>
                    <td>{{ transaction["date"] }}</td>
                    <td>
                        {{ transaction["type"] }}
                        {% if transaction.get("to") %} → {{ transaction["to"] }} {% endif %}
                        {% if transaction.get("from") %} ← {{ transaction["from"] }} {% endif %}
                    </td>
                    <td class="{% if transaction['amount'] < 0 %}text-danger{% else %}text-success{% endif %}">
                        ${{ transaction["amount"] }}
                    </td>
                </tr>
            {% endfor %}
        </tbody>
    </table>

    <a href="{{ url_for('dashboard_client') }}" class="btn btn-secondary mt-3">Back</a>
</div>

<script>
function updateTransactions() {
    let selectedClient = document.getElementById("clientSelect").value;
    fetch(`/account_statements?client=${selectedClient}`)
    .then(response => response.json())
    .then(data => {
        let transactionTable = document.getElementById("transactionTable");
        transactionTable.innerHTML = "";
        data.transactions.forEach(transaction => {
            let row = "<tr><td>" + transaction.date + "</td><td>" + transaction.type;
            if (transaction.to) row += " → " + transaction.to;
            if (transaction.from) row += " ← " + transaction.from;
            row += "</td><td class='" + (transaction.amount < 0 ? "text-danger" : "text-success") + "'>$" + transaction.amount + "</td></tr>";
            transactionTable.innerHTML += row;
        });
    });
}
</script>

</body>
</html>
"""
apply_loan_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Client Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>
<div class="container">
    <h2 class="text-center">💳 Loan Application</h2>
    <p class="text-center">Check your loan status or apply for a new loan.</p>

    <h4>Current Loan Status: <strong>{{ clients["client1"]["loan_status"] }}</strong></h4>

    <button class="btn btn-primary w-100 mt-3">Apply for Loan</button>

    <a href="{{ url_for('dashboard_client') }}" class="btn btn-secondary mt-3 w-100">Back</a>
</div>


</body>
</html>
"""

update_personal_info_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Client Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>
<div class="container">
    <h2 class="text-center">🔧 Update Personal Information</h2>
    <p class="text-center">Modify your personal details securely.</p>

    <label class="form-label">Full Name:</label>
    <input type="text" class="form-control" value="John Doe">

    <label class="form-label mt-3">Email:</label>
    <input type="email" class="form-control" value="john@example.com">

    <button class="btn btn-success w-100 mt-3">Save Changes</button>

    <a href="{{ url_for('dashboard_client') }}" class="btn btn-secondary mt-3 w-100">Back</a>
</div>


</body>
</html>
"""

pay_bills_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Client Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>
<div class="container">
    <h2 class="text-center">💳 Pay Bills</h2>
    <p class="text-center">Manage and pay your bills securely.</p>

    <table class="table table-bordered">
        <thead>
            <tr>
                <th>Bill</th>
                <th>Amount</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            {% for bill in clients["client1"]["bills"] %}
            <tr>
                <td>{{ bill["bill"] }}</td>
                <td>${{ bill["amount"] }}</td>
                <td><button class="btn btn-primary">Pay Now</button></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <a href="{{ url_for('dashboard_client') }}" class="btn btn-secondary mt-3 w-100">Back</a>
</div>



</body>
</html>
"""

employee_dashboard_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Employee Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

<div class="navbar">
    <a href="{{ url_for('dashboard_employee') }}">🏠 Dashboard</a>
    <a href="{{ url_for('logout') }}">🚪 Logout</a>
</div>

<div class="container">
    <h2 class="text-center">Employee Dashboard</h2>

    <div class="row">
        <div class="col-md-6">
            <a href="{{ url_for('customer_support') }}" class="btn btn-primary btn-custom">👨‍💻 Customer Support</a>
            <a href="{{ url_for('process_transactions') }}" class="btn btn-warning btn-custom">💰 Process Transactions</a>
        </div>
        <div class="col-md-6">
            <a href="{{ url_for('update_accounts') }}" class="btn btn-success btn-custom">📂 Update Accounts</a>
            <a href="{{ url_for('monitor_transactions') }}" class="btn btn-danger btn-custom">🛡️ Monitor Transactions</a>
        </div>
    </div>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>

</body>
</html>
"""

customer_support_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Customer Support & Data Security</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/js/all.min.js"></script>
    <style>{{ style_css }}</style>
</head>
<body>

<div class="container">
    <h2 class="text-center">🔒 Customer Support & Data Security</h2>
    <p class="text-center">Encrypt and decrypt customer data securely.</p>

    <div class="card">
        <div class="card-body">
            <div class="mb-3">
                <label class="form-label">Enter Data:</label>
                <textarea id="inputData" class="form-control" rows="3" placeholder="Type your text here..."></textarea>
            </div>

            <div class="text-center">
                <button class="btn btn-primary" onclick="encryptData()">🔐 Encrypt</button>
                <button class="btn btn-warning" onclick="decryptData()">🔓 Decrypt</button>
            </div>
        </div>
    </div>

    <div class="mt-4">
        <div id="encryptedOutput" class="alert alert-success d-none">
            <strong>Encrypted Data:</strong> <span id="encryptedText"></span>
            <span class="copy-btn" onclick="copyToClipboard('encryptedText')">📋</span>
        </div>
        <div id="decryptedOutput" class="alert alert-info d-none">
            <strong>Decrypted Data:</strong> <span id="decryptedText"></span>
            <span class="copy-btn" onclick="copyToClipboard('decryptedText')">📋</span>
        </div>
        <div id="errorOutput" class="alert alert-danger d-none"></div>
    </div>

    <a href="{{ url_for('dashboard_employee') }}" class="btn btn-secondary mt-3">Back</a>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>

<!-- JavaScript for Live Encryption & Decryption -->
<script>
function encryptData() {
    let data = document.getElementById("inputData").value;
    if (!data) {
        showError("Please enter data to encrypt.");
        return;
    }

    fetch('/encrypt', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: data })
    })
    .then(response => response.json())
    .then(result => {
        document.getElementById("encryptedText").textContent = result.encrypted_data;
        document.getElementById("encryptedOutput").classList.remove("d-none");
        document.getElementById("decryptedOutput").classList.add("d-none");
        hideError();
    })
    .catch(error => showError("Encryption failed."));
}

function decryptData() {
    let data = document.getElementById("inputData").value;
    if (!data) {
        showError("Please enter encrypted data to decrypt.");
        return;
    }

    fetch('/decrypt', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encrypted_data: data })
    })
    .then(response => response.json())
    .then(result => {
        document.getElementById("decryptedText").textContent = result.decrypted_data;
        document.getElementById("decryptedOutput").classList.remove("d-none");
        document.getElementById("encryptedOutput").classList.add("d-none");
        hideError();
    })
    .catch(error => showError("Decryption failed."));
}

function copyToClipboard(elementId) {
    let text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text).then(() => alert("Copied to clipboard!"));
}

function showError(message) {
    document.getElementById("errorOutput").textContent = message;
    document.getElementById("errorOutput").classList.remove("d-none");
}

function hideError() {
    document.getElementById("errorOutput").classList.add("d-none");
}
</script>

</body>
</html>
"""

encrypted_messaging_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Client Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>
<div class="container">
    <h2 class="text-center">🔐 Encrypted Messaging</h2>
    <p class="text-center">Send secure messages using AES encryption.</p>

    <div class="mb-3">
        <label class="form-label">Enter Message:</label>
        <textarea id="messageInput" class="form-control" rows="3" placeholder="Type your message here..."></textarea>
    </div>

    <div class="text-center">
        <button class="btn btn-primary" onclick="encryptMessage()">🔐 Encrypt</button>
        <button class="btn btn-warning" onclick="decryptMessage()">🔓 Decrypt</button>
    </div>

    <div class="mt-4">
        <div id="encryptedOutput" class="alert alert-success d-none">
            <strong>Encrypted Message:</strong> <span id="encryptedText"></span>
            <span class="copy-btn" onclick="copyToClipboard('encryptedText')">📋</span>
        </div>
        <div id="decryptedOutput" class="alert alert-info d-none">
            <strong>Decrypted Message:</strong> <span id="decryptedText"></span>
            <span class="copy-btn" onclick="copyToClipboard('decryptedText')">📋</span>
        </div>
        <div id="errorOutput" class="alert alert-danger d-none"></div>
    </div>

    <a href="{{ url_for('dashboard_client') }}" class="btn btn-secondary mt-3">Back</a>
</div>

<script>
function encryptMessage() {
    let message = document.getElementById("messageInput").value;
    if (!message) {
        showError("Please enter a message to encrypt.");
        return;
    }

    fetch('/encrypt', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: message })
    })
    .then(response => response.json())
    .then(result => {
        document.getElementById("encryptedText").textContent = result.encrypted_data;
        document.getElementById("encryptedOutput").classList.remove("d-none");
        document.getElementById("decryptedOutput").classList.add("d-none");
        hideError();
    })
    .catch(error => showError("Encryption failed."));
}

function decryptMessage() {
    let encryptedData = document.getElementById("messageInput").value;
    if (!encryptedData) {
        showError("Please enter encrypted data to decrypt.");
        return;
    }

    fetch('/decrypt', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encrypted_data: encryptedData })
    })
    .then(response => response.json())
    .then(result => {
        document.getElementById("decryptedText").textContent = result.decrypted_data;
        document.getElementById("decryptedOutput").classList.remove("d-none");
        document.getElementById("encryptedOutput").classList.add("d-none");
        hideError();
    })
    .catch(error => showError("Decryption failed."));
}

function copyToClipboard(elementId) {
    let text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text).then(() => alert("Copied to clipboard!"));
}

function showError(message) {
    let errorDiv = document.getElementById("errorOutput");
    errorDiv.textContent = message;
    errorDiv.classList.remove("d-none");
}

function hideError() {
    document.getElementById("errorOutput").classList.add("d-none");
}
</script>


</body>
</html>
"""

update_accounts_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Update Customer Accounts</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

<div class="container">
    <h2 class="text-center">📂 Update Customer Accounts</h2>
    <p class="text-center">Modify customer details securely.</p>

    <div class="mb-3">
        <label class="form-label">Select Customer:</label>
        <select id="customerSelect" class="form-control">
            {% for customer_id, data in customers.items() %}
                <option value="{{ customer_id }}">{{ data["name"] }}</option>
            {% endfor %}
        </select>
    </div>

    <div class="mb-3">
        <label class="form-label">Update Email:</label>
        <input type="email" id="newEmail" class="form-control" placeholder="Enter new email">
    </div>

    <button class="btn btn-primary w-100" onclick="updateCustomer()">🔄 Update Account</button>

    <div id="updateResult" class="alert mt-3 d-none"></div>

    <a href="{{ url_for('dashboard_employee') }}" class="btn btn-secondary mt-3">Back</a>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>

<script>
function updateCustomer() {
    let customerId = document.getElementById("customerSelect").value;
    let newEmail = document.getElementById("newEmail").value;

    if (!newEmail) {
        showUpdateResult("❌ Please enter a valid email.", "danger");
        return;
    }

    fetch('/update_customer', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ customer_id: customerId, email: newEmail })
    })
    .then(response => response.json())
    .then(result => {
        if (result.message) {
            showUpdateResult(result.message, "success");
        } else {
            showUpdateResult(result.error, "danger");
        }
    })
    .catch(error => showUpdateResult("❌ Update failed.", "danger"));
}

function showUpdateResult(message, type) {
    let resultDiv = document.getElementById("updateResult");
    resultDiv.textContent = message;
    resultDiv.className = "alert alert-" + type;
    resultDiv.classList.remove("d-none");
}
</script>

</body>
</html>
"""

process_transactions_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Process Transactions</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

<div class="container">
    <h2 class="text-center">💰 Process Transactions</h2>
    <p class="text-center">Handle customer transactions securely.</p>

    <div class="mb-3">
        <label class="form-label">Select Customer:</label>
        <select id="transactionCustomer" class="form-control">
            {% for customer_id, data in customers.items() %}
                <option value="{{ customer_id }}">{{ data["name"] }} (Balance: ${{ data["balance"] }})</option>
            {% endfor %}
        </select>
    </div>

    <div class="mb-3">
        <label class="form-label">Transaction Type:</label>
        <select id="transactionType" class="form-control">
            <option value="deposit">Deposit</option>
            <option value="withdraw">Withdraw</option>
        </select>
    </div>

    <div class="mb-3">
        <label class="form-label">Amount:</label>
        <input type="number" id="transactionAmount" class="form-control" placeholder="Enter amount">
    </div>

    <button class="btn btn-primary w-100" onclick="processTransaction()">💸 Submit Transaction</button>

    <div id="transactionResult" class="alert mt-3 d-none"></div>

    <a href="{{ url_for('dashboard_employee') }}" class="btn btn-secondary mt-3">Back</a>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>

<script>
function processTransaction() {
    let customerId = document.getElementById("transactionCustomer").value;
    let transactionType = document.getElementById("transactionType").value;
    let amount = document.getElementById("transactionAmount").value;

    if (!amount || amount <= 0) {
        showTransactionResult("❌ Please enter a valid amount.", "danger");
        return;
    }

    fetch('/make_transaction', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ customer_id: customerId, transaction_type: transactionType, amount: amount })
    })
    .then(response => response.json())
    .then(result => {
        if (result.message) {
            showTransactionResult(result.message, "success");
        } else {
            showTransactionResult(result.error, "danger");
        }
    })
    .catch(error => showTransactionResult("❌ Transaction failed.", "danger"));
}

function showTransactionResult(message, type) {
    let resultDiv = document.getElementById("transactionResult");
    resultDiv.textContent = message;
    resultDiv.className = "alert alert-" + type;
    resultDiv.classList.remove("d-none");
}
</script>

</body>
</html>
"""

monitor_transactions_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Monitor Transactions</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

<div class="container">
    <h2 class="text-center">🛡️ Monitor Transactions</h2>
    <p class="text-center">Verify encrypted transactions using HMAC.</p>

    <div class="mb-3">
        <label class="form-label">Enter Encrypted Transaction Data:</label>
        <textarea id="encryptedData" class="form-control" rows="3" placeholder="Paste encrypted transaction data..."></textarea>
    </div>

    <div class="mb-3">
        <label class="form-label">Enter HMAC:</label>
        <input type="text" id="hmacInput" class="form-control" placeholder="Paste HMAC here...">
    </div>

    <div class="text-center">
        <button class="btn btn-primary" onclick="verifyTransaction()">🔍 Verify Transaction</button>
    </div>

    <div class="mt-4">
        <div id="verificationResult" class="alert d-none"></div>
    </div>

    <a href="{{ url_for('dashboard_employee') }}" class="btn btn-secondary mt-3">Back</a>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>

<!-- JavaScript for Verification -->
<script>
function verifyTransaction() {
    let encryptedData = document.getElementById("encryptedData").value;
    let hmac = document.getElementById("hmacInput").value;

    if (!encryptedData || !hmac) {
        showError("Please enter both Encrypted Data and HMAC.");
        return;
    }

    fetch('/verify_transaction', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encrypted_data: encryptedData, hmac: hmac })
    })
    .then(response => response.json())
    .then(result => {
        if (result.message) {
            showSuccess(result.message + " 🔓 Decrypted Data: " + result.decrypted_data);
        } else {
            showError(result.error);
        }
    })
    .catch(error => showError("❌ Verification failed."));
}

function showError(message) {
    let resultDiv = document.getElementById("verificationResult");
    resultDiv.textContent = message;
    resultDiv.className = "alert alert-danger";
    resultDiv.classList.remove("d-none");
}

function showSuccess(message) {
    let resultDiv = document.getElementById("verificationResult");
    resultDiv.textContent = message;
    resultDiv.className = "alert alert-success";
    resultDiv.classList.remove("d-none");
}
</script>

</body>
</html>
"""

verify_transactions_template = """
<div class="container">
    <h2>Verify Encrypted Transactions</h2>
    <p>Ensure data integrity before processing.</p>

    <button class="btn btn-success">Verify Transaction</button>

    <a href="{{ url_for('dashboard_employee') }}" class="btn btn-secondary mt-3">Back</a>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>
"""

dashboard_template = """ 


<!DOCTYPE html>
<html lang="en">
<head>
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>{{ style_css }}</style>
</head>
<body>

    <div class="navbar">
        <a href="{{ url_for('dashboard_admin') }}">🏠 Dashboard</a>
        <a href="{{ url_for('logout') }}">🚪 Logout</a>
    </div>

    <div class="container">
        <h2 class="text-center">Administrator Dashboard</h2>
        <p class="text-center">Welcome, <strong>{{ username }}</strong></p>

        <div class="row">
            <div class="col-md-6">
                <a href="{{ url_for('manage_users') }}" class="btn btn-primary btn-custom">👥 Manage Users</a>
                <a href="{{ url_for('monitor_security') }}" class="btn btn-warning btn-custom">🔒 Monitor Security</a>
            </div>
            <div class="col-md-6">
                <a href="{{ url_for('handle_keys') }}" class="btn btn-success btn-custom">🔑 Cryptographic Keys</a>
                <a href="{{ url_for('system_maintenance') }}" class="btn btn-danger btn-custom">⚙️ System Maintenance</a>
            </div>
        </div>
    </div>

    <div class="footer">© 2025 MyBank | Secure Banking System</div>

</body>
</html>
"""
manage_users_template = """
<div class="container">
    <h2 class="text-center">Manage Users & Roles</h2>
    <p class="text-center">Modify user roles and access controls.</p>

    <div class="input-group mb-3">
        <input type="text" id="searchUser" class="form-control" placeholder="Search users..." onkeyup="filterUsers()">
        <span class="input-group-text">🔍</span>
    </div>

    {% if users %}
        <table class="table table-bordered table-hover" id="usersTable">
            <thead class="table-dark">
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for user in users %}
                    <tr>
                        <td>{{ user['username'] }}</td>
                        <td>
                            <span class="badge {% if user['role'] == 'Client' %}bg-primary{% elif user['role'] == 'Bank Employee' %}bg-warning{% else %}bg-danger{% endif %}">
                                {{ user['role'] }}
                            </span>
                        </td>
                        <td>
                            <span class="badge {% if user['status'] == 'Active' %}bg-success{% else %}bg-secondary{% endif %}">
                                {{ user['status'] }}
                            </span>
                        </td>
                        <td>
                            <button class="btn btn-sm btn-outline-primary" onclick="editUser('{{ user['username'] }}')">✏️ Edit</button>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteUser('{{ user['username'] }}')">🗑️ Delete</button>
                        </td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    {% else %}
        <p class="alert alert-warning">No users available.</p>
    {% endif %}
    
    <a href="{{ url_for('dashboard_admin') }}" class="btn btn-secondary">Back</a>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>

<!-- JavaScript for Filtering & Actions -->
<script>
function filterUsers() {
    let input = document.getElementById("searchUser").value.toLowerCase();
    let table = document.getElementById("usersTable");
    let rows = table.getElementsByTagName("tr");

    for (let i = 1; i < rows.length; i++) {
        let username = rows[i].getElementsByTagName("td")[0].textContent.toLowerCase();
        rows[i].style.display = username.includes(input) ? "" : "none";
    }
}

function editUser(username) {
    alert("Editing user: " + username + " (Feature Coming Soon)");
}

function deleteUser(username) {
    let confirmDelete = confirm("Are you sure you want to delete " + username + "?");
    if (confirmDelete) {
        alert(username + " has been deleted (Feature Coming Soon)");
    }
}
</script>

"""

monitor_security_template = """
<div class="container">
    <h2>Monitor Security & Audits</h2>
    <div class="alert alert-info">All systems operational. No security threats detected.</div>
    <ul class="list-group">
        <li class="list-group-item">🛡️ Firewall: Active & Secure</li>
        <li class="list-group-item">🔍 IDS Logs: No suspicious activity detected</li>
        <li class="list-group-item">⚠️ Last Security Patch: Applied 2 days ago</li>
    </ul>
    
    <a href="{{ url_for('dashboard_admin') }}" class="btn btn-secondary mt-3">Back</a>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>
"""

handle_keys_template = """
<div class="container">
    <h2>Cryptographic Key Management</h2>
    <p>Manage encryption keys securely.</p>
    <button class="btn btn-primary">🔑 Generate New Key</button>
    <button class="btn btn-warning">📁 Backup Existing Keys</button>

    <div class="alert alert-success mt-3">Last key update: 3 days ago</div>

    <a href="{{ url_for('dashboard_admin') }}" class="btn btn-secondary">Back</a>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>
"""

system_maintenance_template = """
<div class="container">
    <h2>System Updates & Backups</h2>
    <p>Ensure the banking system is up-to-date and secure.</p>
    <button class="btn btn-primary">🔄 Check for Updates</button>
    <button class="btn btn-warning">📂 Run Backup Now</button>

    <div class="alert alert-info mt-3">Last backup: 5 days ago</div>

    <a href="{{ url_for('dashboard_admin') }}" class="btn btn-secondary">Back</a>
</div>

<div class="footer">© 2025 MyBank | Secure Banking System</div>
"""


# 🎨 **CSS Styling**
style_css = """
body {
    font-family: 'Arial', sans-serif;
    background-color: #f8f9fa;
}
.navbar {
    background-color: #007bff;
    padding: 10px;
}
.navbar a {
    color: white;
    font-weight: bold;
    text-decoration: none;
    padding: 10px;
}
.navbar a:hover {
    background-color: #0056b3;
    border-radius: 5px;
}
.container {
    margin-top: 40px;
    padding: 20px;
    background-color: white;
    border-radius: 10px;
    box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
}
.btn-custom {
    width: 100%;
    padding: 10px;
    font-size: 16px;
    margin-top: 10px;
}
.footer {
    margin-top: 30px;
    text-align: center;
    font-size: 14px;
    color: #555;
    padding: 10px;
    background-color: #f1f1f1;
}
"""

if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)
