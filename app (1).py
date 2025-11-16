# /home/dodo1/mysite/app.py
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from werkzeug.utils import secure_filename
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from PIL import Image
import io

app = Flask(__name__)
app.secret_key = 'change_this_to_a_random_string'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['EDITED_PDF_FOLDER'] = 'edited_pdfs'
app.config['PDF_FOLDER'] = 'pdfs'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'png', 'jpg', 'jpeg'}

# -------------------------------------------------
# DB INITIALISATION (runs once on import)
# -------------------------------------------------
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # users
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL)''')

    # files
    c.execute('''CREATE TABLE IF NOT EXISTS files (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 filename TEXT,
                 original_name TEXT,
                 FOREIGN KEY(user_id) REFERENCES users(id))''')

    # chat messages
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT,
                 message TEXT,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    # pdf_templates (new)
    c.execute('''CREATE TABLE IF NOT EXISTS pdf_templates (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER NOT NULL,
                 name TEXT NOT NULL,
                 filename TEXT NOT NULL,
                 UNIQUE(user_id, name),
                 FOREIGN KEY(user_id) REFERENCES users(id))''')

    conn.commit()
    conn.close()

# Run DB init **once** when the module is imported
init_db()

# -------------------------------------------------
# Helper decorators
# -------------------------------------------------
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------------------------------
# Routes
# -------------------------------------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT id, username FROM users WHERE username=? AND password=?',
                  (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?,?)',
                      (username, password))
            conn.commit()
            flash('Account created – please log in')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken')
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # ---- clean orphan file entries ----
    c.execute('SELECT id, filename FROM files WHERE user_id=?', (session['user_id'],))
    for fid, fn in c.fetchall():
        p1 = os.path.join(app.config['UPLOAD_FOLDER'], fn)
        p2 = os.path.join(app.config['EDITED_PDF_FOLDER'], fn)
        if not (os.path.exists(p1) or os.path.exists(p2)):
            c.execute('DELETE FROM files WHERE id=?', (fid,))

    # ---- fetch user files ----
    c.execute('''SELECT id, original_name, filename FROM files
                 WHERE user_id=? ORDER BY id DESC''', (session['user_id'],))
    files = c.fetchall()
    conn.commit()
    conn.close()
    return render_template('dashboard.html',
                           files=files,
                           username=session['username'])

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique = f"{session['user_id']}_{os.urandom(8).hex()}_{filename}"
        path = os.path.join(app.config['UPLOAD_FOLDER'], unique)
        file.save(path)

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO files (user_id, filename, original_name) VALUES (?,?,?)',
                  (session['user_id'], unique, filename))
        conn.commit()
        conn.close()
    return redirect(url_for('dashboard'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT filename, original_name FROM files WHERE id=? AND user_id=?',
              (file_id, session['user_id']))
    data = c.fetchone()
    conn.close()
    if not data:
        flash('File not found')
        return redirect(url_for('dashboard'))

    filename, original = data
    # try uploads first, then edited_pdfs
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(path):
        path = os.path.join(app.config['EDITED_PDF_FOLDER'], filename)

    return send_file(path, as_attachment=True, download_name=original)

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT filename FROM files WHERE id=? AND user_id=?',
              (file_id, session['user_id']))
    row = c.fetchone()
    if row:
        fn = row[0]
        for folder in (app.config['UPLOAD_FOLDER'], app.config['EDITED_PDF_FOLDER']):
            p = os.path.join(folder, fn)
            if os.path.exists(p):
                os.remove(p)
        c.execute('DELETE FROM files WHERE id=?', (file_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

# -------------------------------------------------
# PDF Editor (templates)
# -------------------------------------------------
@app.route('/pdf-editor')
@login_required
def pdf_editor():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, name FROM pdf_templates WHERE user_id=?',
              (session['user_id'],))
    templates = c.fetchall()
    conn.close()
    return render_template('pdf_editor.html', templates=templates)

# -------------------------------------------------
# Image → PDF page
# -------------------------------------------------
@app.route('/image-to-pdf')
@login_required
def image_to_pdf_page():
    return render_template('image_to_pdf.html')

# -------------------------------------------------
# Global Chat
# -------------------------------------------------
@app.route('/chat')
@login_required
def chat():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT username, message, timestamp FROM messages ORDER BY timestamp')
    msgs = c.fetchall()
    conn.close()
    return render_template('chat.html', messages=msgs, username=session['username'])

@app.route('/send-message', methods=['POST'])
@login_required
def send_message():
    msg = request.form.get('message', '').strip()
    if msg:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO messages (username, message) VALUES (?,?)',
                  (session['username'], msg))
        conn.commit()
        conn.close()
    return redirect(url_for('chat'))

# -------------------------------------------------
# Logout
# -------------------------------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# -------------------------------------------------
# Run (only for local testing)
# -------------------------------------------------
if __name__ == '__main__':
    # create folders if missing
    for folder in (app.config['UPLOAD_FOLDER'],
                   app.config['EDITED_PDF_FOLDER'],
                   app.config['PDF_FOLDER']):
        os.makedirs(folder, exist_ok=True)
    app.run(debug=True)
    
