from flask import Flask, render_template, request, redirect, session, flash, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from PyPDF2 import PdfReader
from PIL import Image
import pytesseract
import os
import re
import cv2

# ===============================
# APP CONFIG
# ===============================

app = Flask(__name__)
app.secret_key = 'cybershield_secret_key'

print("App Starting...")

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ===============================
# MYSQL DATABASE CONFIGURATION
# ===============================

def get_db():

    db = mysql.connector.connect(
        host=os.getenv("MYSQL_ADDON_HOST"),
        user=os.getenv("MYSQL_ADDON_USER"),
        password=os.getenv("MYSQL_ADDON_PASSWORD"),
        database=os.getenv("MYSQL_ADDON_DB"),
        port=int(os.getenv("MYSQL_ADDON_PORT", 3306))
    )

    return db, db.cursor(dictionary=True)

try:

    db, cursor = get_db()

    print("Database Connected Successfully")

except Exception as e:

    print("Database Connection Error:", e)

    db = None
    cursor = None

print("DB Setup Complete")

# ===============================
# OCR FUNCTION
# ===============================

def extract_text(image_path):

    try:

        img = cv2.imread(image_path)

        if img is None:
            return "Unable to read image"

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        gray = cv2.threshold(
            gray,
            150,
            255,
            cv2.THRESH_BINARY
        )[1]

        text = pytesseract.image_to_string(gray)

        return text

    except Exception as e:

        return f"OCR Error: {str(e)}"

# ===============================
# URL ANALYZER
# ===============================

def analyze_url(url):

    score = 100
    reasons = []

    phishing_keywords = [
        "signin",
        "verify",
        "verify-account",
        "update-bank",
        "freegift",
        "claim-prize",
        "login",
        "secure-login",
        "banking",
        "wallet-update",
        "gift",
        "bonus"
    ]

    suspicious_tlds = [
        ".tk",
        ".xyz",
        ".ru",
        ".cn",
        ".top",
        ".gq"
    ]

    blacklist = [
        "malicious-site.com",
        "fakebank.xyz",
        "phishing-login.ru"
    ]

    if not url.startswith("https://"):
        score -= 20
        reasons.append("Website does not use HTTPS secure protocol")

    if "@" in url:
        score -= 15
        reasons.append("URL contains suspicious '@' symbol")

    if url.count(".") > 3:
        score -= 10
        reasons.append("URL contains multiple dots")

    if "-" in url:
        score -= 10
        reasons.append("URL contains suspicious '-' symbol")

    if len(url) > 60:
        score -= 10
        reasons.append("URL length is unusually long")

    for keyword in phishing_keywords:

        if keyword.lower() in url.lower():

            score -= 10
            reasons.append(f"Suspicious keyword detected: {keyword}")

    for tld in suspicious_tlds:

        if tld in url:

            score -= 15
            reasons.append(f"Suspicious domain extension detected: {tld}")

    for bad in blacklist:

        if bad in url:

            score -= 40
            reasons.append("Website found in phishing blacklist")

    if score >= 75:

        status = "Safe"
        color = "success"

    elif score >= 45:

        status = "Warning"
        color = "warning"

    else:

        status = "Dangerous"
        color = "danger"

    phishing_probability = 100 - score

    recommendations = [
        "Always verify website domain carefully",
        "Avoid entering passwords on suspicious websites",
        "Check HTTPS and SSL certificate",
        "Never click unknown email links"
    ]

    return {
        "score": score,
        "status": status,
        "color": color,
        "probability": phishing_probability,
        "reasons": reasons,
        "recommendations": recommendations
    }

# ===============================
# HOME PAGE
# ===============================

@app.route('/landing')
def landing():
    return render_template('landing.html')

# ===============================
# REGISTER
# ===============================

@app.route('/register', methods=['GET', 'POST'])
def register():

    if cursor is None:
        return "Database not connected"

    if request.method == 'POST':

        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        cursor.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:

            flash("Email already exists", "danger")
            return redirect('/register')

        sql = """
        INSERT INTO users(name, email, password)
        VALUES(%s, %s, %s)
        """

        values = (name, email, hashed_password)

        cursor.execute(sql, values)
        db.commit()

        flash("Registration Successful", "success")

        return redirect('/login')

    return render_template('register.html')

# ===============================
# LOGIN
# ===============================

@app.route('/login', methods=['GET', 'POST'])
def login():

    if cursor is None:
        return "Database not connected"

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        cursor.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )

        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):

            session['loggedin'] = True
            session['id'] = user['id']
            session['name'] = user['name']
            session['email'] = user['email']
            session['role'] = user['role']

            flash("Login Successful", "success")

            if user['role'] == 'admin':
                return redirect('/admin')

            return redirect('/dashboard')

        else:

            flash("Invalid Email or Password", "danger")
            return redirect('/login')

    return render_template('login.html')

# ===============================
# LOGOUT
# ===============================

@app.route('/logout')
def logout():

    session.clear()

    flash("Logged out successfully", "info")

    return redirect('/')

# ===============================
# DASHBOARD
# ===============================

@app.route('/dashboard')
def dashboard():

    if cursor is None:
        return "Database not connected"

    if 'loggedin' not in session:
        return redirect('/login')

    user_id = session['id']

    cursor.execute(
        "SELECT COUNT(*) AS total FROM scan_reports WHERE user_id=%s",
        (user_id,)
    )

    total_scans = cursor.fetchone()['total']

    return render_template(
        'dashboard.html',
        total_scans=total_scans
    )

# ===============================
# SCANNER PAGE
# ===============================

@app.route('/scanner')
def scanner():

    if 'loggedin' not in session:
        return redirect('/login')

    return render_template('scanner.html')

# ===============================
# URL SCANNER API
# ===============================

@app.route('/scan_url', methods=['POST'])
def scan_url():

    if cursor is None:
        return jsonify({"error": "Database not connected"})

    if 'loggedin' not in session:
        return jsonify({"error": "Unauthorized"})

    data = request.get_json()

    url = data.get('url')

    result = analyze_url(url)

    sql = """
    INSERT INTO scan_reports(user_id, url, score, result)
    VALUES(%s, %s, %s, %s)
    """

    values = (
        session['id'],
        url,
        result['score'],
        result['status']
    )

    cursor.execute(sql, values)
    db.commit()

    return jsonify(result)

# ===============================
# REPORTS PAGE
# ===============================

@app.route('/reports')
def reports():

    if cursor is None:
        return "Database not connected"

    if 'loggedin' not in session:
        return redirect('/login')

    cursor.execute("""
        SELECT * FROM scan_reports
        WHERE user_id=%s
        ORDER BY scan_date DESC
    """, (session['id'],))

    reports = cursor.fetchall()

    return render_template(
        'reports.html',
        reports=reports
    )

# ===============================
# AWARENESS PAGE
# ===============================

@app.route('/awareness')
def awareness():
    return render_template('awareness.html')

# ===============================
# CONTACT PAGE
# ===============================

@app.route('/contact', methods=['GET', 'POST'])
def contact():

    if cursor is None:
        return "Database not connected"

    if request.method == 'POST':

        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        sql = """
        INSERT INTO contact_reports(name, email, message)
        VALUES(%s, %s, %s)
        """

        values = (name, email, message)

        cursor.execute(sql, values)
        db.commit()

        flash("Report submitted successfully", "success")

        return redirect('/contact')

    return render_template('contact.html')

# ===============================
# ADMIN PANEL
# ===============================

@app.route('/admin')
def admin():

    if cursor is None:
        return "Database not connected"

    if 'loggedin' not in session:
        return redirect('/login')

    if session['role'] != 'admin':
        return redirect('/dashboard')

    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    cursor.execute("""
        SELECT scan_reports.*, users.name
        FROM scan_reports
        JOIN users ON users.id = scan_reports.user_id
        ORDER BY scan_date DESC
    """)

    reports = cursor.fetchall()

    return render_template(
        'admin.html',
        users=users,
        reports=reports
    )

# ===============================
# DELETE REPORT
# ===============================

@app.route('/delete_report/<int:id>')
def delete_report(id):

    if cursor is None:
        return "Database not connected"

    if 'loggedin' not in session:
        return redirect('/login')

    cursor.execute(
        "DELETE FROM scan_reports WHERE id=%s",
        (id,)
    )

    db.commit()

    flash("Report Deleted", "warning")

    return redirect('/admin')

# ===============================
# PDF SCANNER
# ===============================

@app.route('/pdf_scanner', methods=['GET', 'POST'])
def pdf_scanner():

    result = None

    if request.method == 'POST':

        pdf_file = request.files['pdf_file']

        filepath = os.path.join(
            UPLOAD_FOLDER,
            pdf_file.filename
        )

        pdf_file.save(filepath)

        reader = PdfReader(filepath)

        text = ''

        for page in reader.pages:

            extracted = page.extract_text()

            if extracted:
                text += extracted

        suspicious_keywords = [
            'verify account',
            'bank login',
            'claim prize',
            'free gift',
            'urgent payment'
        ]

        detected = []

        for word in suspicious_keywords:

            if word.lower() in text.lower():
                detected.append(word)

        if detected:
            result = 'Suspicious PDF Detected'
        else:
            result = 'PDF Looks Safe'

    return render_template(
        'pdf_scanner.html',
        result=result
    )

# ===============================
# IMAGE SCANNER
# ===============================

@app.route('/image_scanner', methods=['GET', 'POST'])
def image_scanner():

    result = None
    extracted_text = ''

    if request.method == 'POST':

        image = request.files['image']

        filepath = os.path.join(
            UPLOAD_FOLDER,
            image.filename
        )

        image.save(filepath)

        extracted_text = extract_text(filepath)

        phishing_words = [
            'bank login',
            'otp',
            'verify',
            'claim reward',
            'update account'
        ]

        suspicious = any(
            word in extracted_text.lower()
            for word in phishing_words
        )

        result = (
            'Phishing Image Detected'
            if suspicious
            else 'Image Looks Safe'
        )

    return render_template(
        'image_scanner.html',
        result=result,
        extracted_text=extracted_text
    )

# ===============================
# SMS SCANNER
# ===============================

@app.route('/sms_scanner', methods=['GET', 'POST'])
def sms_scanner():

    result = None

    if request.method == 'POST':

        sms = request.form['sms']

        keywords = [
            'win money',
            'claim prize',
            'urgent',
            'verify account',
            'bank suspended',
            'click link',
            'free reward'
        ]

        detected = []

        for word in keywords:

            if word.lower() in sms.lower():
                detected.append(word)

        if detected:
            result = 'Phishing SMS Detected'
        else:
            result = 'SMS Looks Safe'

    return render_template(
        'sms_scanner.html',
        result=result
    )

# ===============================
# QR SCANNER
# ===============================

@app.route('/qr_scanner', methods=['GET', 'POST'])
def qr_scanner():

    result = None
    qr_data = None

    if request.method == 'POST':

        try:

            from pyzbar.pyzbar import decode

            qr_image = request.files['qr_image']

            filepath = os.path.join(
                UPLOAD_FOLDER,
                qr_image.filename
            )

            qr_image.save(filepath)

            img = Image.open(filepath)

            decoded_objects = decode(img)

            if decoded_objects:

                qr_data = decoded_objects[0].data.decode('utf-8')

                suspicious = any(
                    k in qr_data.lower()
                    for k in ['login', 'verify', 'bank', 'gift']
                )

                result = (
                    "Suspicious QR Code Detected"
                    if suspicious
                    else "QR Code Looks Safe"
                )

            else:

                result = "No QR Code Detected"

        except Exception as e:

            result = f"QR Error: {str(e)}"

    return render_template(
        'qr_scanner.html',
        result=result,
        qr_data=qr_data
    )

# ===============================
# EMAIL SCANNER
# ===============================

@app.route('/email_scanner', methods=['GET', 'POST'])
def email_scanner():

    result = None
    detected = []

    if request.method == 'POST':

        email_content = request.form['email_content']

        phishing_keywords = [

            'verify account',
            'click here',
            'urgent action',
            'bank suspended',
            'payment failed',
            'claim reward',
            'login immediately',
            'limited offer',
            'free gift',
            'update account',
            'otp',
            'wallet',
            'security alert',
            'account blocked',
            'confirm identity',
            'win iphone',
            'prize',
            'crypto reward',
            'bitcoin',
            'airdrop'
        ]

        for keyword in phishing_keywords:

            if keyword.lower() in email_content.lower():
                detected.append(keyword)

        urls = re.findall(r'https?://\S+', email_content)

        for url in urls:

            if '.ru' in url or '.tk' in url or '.xyz' in url:
                detected.append("Suspicious URL Found")

        if detected:
            result = "Phishing Email Detected"
        else:
            result = "Email Looks Safe"

    return render_template(
        'email_scanner.html',
        result=result,
        detected=detected
    )

# ===============================
# MAIN
# ===============================

if __name__ == '__main__':

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host='0.0.0.0',
        port=port
    )