from flask import Flask, render_template, request, session, redirect, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PyPDF2 import PdfReader, PdfWriter
from PIL import Image
import os
import sqlite3
from datetime import datetime
import io

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'
UPLOAD_FOLDER = '/home/dodo1/mysite/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

# Create uploads folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

def init_db():
    conn = sqlite3.connect('/home/dodo1/mysite/data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY, user_id INTEGER, filename TEXT, filepath TEXT, upload_date TEXT)''')
    conn.commit()
    conn.close()

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('username') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('register.html', error='Username and password required')
        
        try:
            conn = sqlite3.connect('/home/dodo1/mysite/data.db')
            c = conn.cursor()
            hashed_password = generate_password_hash(password)
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('/home/dodo1/mysite/data.db')
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('/home/dodo1/mysite/data.db')
    c = conn.cursor()
    c.execute('SELECT id, filename, upload_date FROM files WHERE user_id = ? ORDER BY upload_date DESC', (session['user_id'],))
    files = c.fetchall()
    conn.close()
    
    return render_template('dashboard.html', files=files, username=session['username'])

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('upload.html', error='No file selected')
        
        file = request.files['file']
        if file.filename == '':
            return render_template('upload.html', error='No file selected')
        
        if not allowed_file(file.filename):
            return render_template('upload.html', error='File type not allowed')
        
        try:
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            unique_filename = f"{session['user_id']}_{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            file.save(filepath)
            
            conn = sqlite3.connect('/home/dodo1/mysite/data.db')
            c = conn.cursor()
            upload_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c.execute('INSERT INTO files (user_id, filename, filepath, upload_date) VALUES (?, ?, ?, ?)',
                     (session['user_id'], filename, filepath, upload_date))
            conn.commit()
            conn.close()
            
            return redirect(url_for('dashboard'))
        except Exception as e:
            return render_template('upload.html', error=f'Upload failed: {str(e)}')
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    try:
        conn = sqlite3.connect('/home/dodo1/mysite/data.db')
        c = conn.cursor()
        c.execute('SELECT filepath, filename FROM files WHERE id = ? AND user_id = ?', 
                 (file_id, session['user_id']))
        file_data = c.fetchone()
        conn.close()
        
        if not file_data:
            return "File not found", 404
        
        filepath, filename = file_data
        
        if not os.path.exists(filepath):
            return "File not found on server", 404
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return f"Error downloading file: {str(e)}", 500

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    try:
        conn = sqlite3.connect('/home/dodo1/mysite/data.db')
        c = conn.cursor()
        c.execute('SELECT filepath FROM files WHERE id = ? AND user_id = ?', 
                 (file_id, session['user_id']))
        file_data = c.fetchone()
        
        if not file_data:
            conn.close()
            return redirect(url_for('dashboard'))
        
        filepath = file_data[0]
        
        if os.path.exists(filepath):
            os.remove(filepath)
        
        c.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        pass
    
    return redirect(url_for('dashboard'))

@app.route('/merge-pdf', methods=['GET', 'POST'])
@login_required
def merge_pdf():
    if request.method == 'POST':
        try:
            pdf_ids = request.form.getlist('pdf_ids')
            
            if not pdf_ids or len(pdf_ids) < 2:
                return render_template('merge_pdf.html', error='Select at least 2 PDFs to merge')
            
            pdf_merger = PdfWriter()
            
            for pdf_id in pdf_ids:
                conn = sqlite3.connect('/home/dodo1/mysite/data.db')
                c = conn.cursor()
                c.execute('SELECT filepath FROM files WHERE id = ? AND user_id = ?', 
                         (pdf_id, session['user_id']))
                file_data = c.fetchone()
                conn.close()
                
                if file_data:
                    filepath = file_data[0]
                    if os.path.exists(filepath) and filepath.lower().endswith('.pdf'):
                        pdf_reader = PdfReader(filepath)
                        for page in pdf_reader.pages:
                            pdf_merger.add_page(page)
            
            output = io.BytesIO()
            pdf_merger.write(output)
            output.seek(0)
            
            return send_file(output, mimetype='application/pdf', as_attachment=True, download_name='merged.pdf')
        except Exception as e:
            return render_template('merge_pdf.html', error=f'Merge failed: {str(e)}')
    
    conn = sqlite3.connect('/home/dodo1/mysite/data.db')
    c = conn.cursor()
    c.execute('SELECT id, filename FROM files WHERE user_id = ? AND filename LIKE ?', 
             (session['user_id'], '%.pdf'))
    pdf_files = c.fetchall()
    conn.close()
    
    return render_template('merge_pdf.html', files=pdf_files)

@app.route('/image-to-pdf', methods=['GET', 'POST'])
@login_required
def image_to_pdf():
    if request.method == 'POST':
        try:
            image_ids = request.form.getlist('image_ids')
            
            if not image_ids:
                return render_template('image_to_pdf.html', error='Select at least 1 image')
            
            images = []
            
            for image_id in image_ids:
                conn = sqlite3.connect('/home/dodo1/mysite/data.db')
                c = conn.cursor()
                c.execute('SELECT filepath FROM files WHERE id = ? AND user_id = ?', 
                         (image_id, session['user_id']))
                file_data = c.fetchone()
                conn.close()
                
                if file_data:
                    filepath = file_data[0]
                    if os.path.exists(filepath):
                        img = Image.open(filepath).convert('RGB')
                        images.append(img)
            
            if not images:
                return render_template('image_to_pdf.html', error='No valid images found')
            
            output = io.BytesIO()
            images[0].save(output, format='PDF', save_all=True, append_images=images[1:])
            output.seek(0)
            
            return send_file(output, mimetype='application/pdf', as_attachment=True, download_name='images.pdf')
        except Exception as e:
            return render_template('image_to_pdf.html', error=f'Conversion failed: {str(e)}')
    
    conn = sqlite3.connect('/home/dodo1/mysite/data.db')
    c = conn.cursor()
    c.execute('SELECT id, filename FROM files WHERE user_id = ? AND (filename LIKE ? OR filename LIKE ? OR filename LIKE ? OR filename LIKE ?)', 
             (session['user_id'], '%.png', '%.jpg', '%.jpeg', '%.gif'))
    image_files = c.fetchall()
    conn.close()
    
    return render_template('image_to_pdf.html', files=image_files)

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=False)
