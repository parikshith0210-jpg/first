# app.py
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from functools import wraps
from datetime import datetime
from PIL import Image
import io
# FIX: Replaced PyPDF2 with the current library, pypdf
from pypdf import PdfReader, PdfWriter 
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Use absolute paths for PythonAnywhere compatibility
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['PDF_FOLDER'] = os.path.join(BASE_DIR, 'pdfs')
app.config['EDITED_PDF_FOLDER'] = os.path.join(BASE_DIR, 'edited_pdfs')
app.config['DATABASE'] = os.path.join(BASE_DIR, 'users.db')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['ALLOWED_IMAGE_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

# Create folders if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PDF_FOLDER'], exist_ok=True)
os.makedirs(app.config['EDITED_PDF_FOLDER'], exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  filename TEXT NOT NULL,
                  original_filename TEXT NOT NULL,
                  upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  username TEXT NOT NULL,
                  message TEXT NOT NULL,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS pdfs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  filename TEXT NOT NULL,
                  original_name TEXT NOT NULL,
                  image_count INTEGER NOT NULL,
                  created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    conn.commit()
    conn.close()

init_db()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        
        try:
            hashed_password = generate_password_hash(password)
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                     (username, hashed_password))
            conn.commit()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'error')
        finally:
            conn.close()
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Clean up orphaned file records (files in database but not on disk)
    c.execute('SELECT id, filename FROM files WHERE user_id = ?', (session['user_id'],))
    all_files = c.fetchall()
    for file_id, filename in all_files:
        # Check in both uploads and edited_pdfs folders
        filepath1 = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        filepath2 = os.path.join(app.config['EDITED_PDF_FOLDER'], filename)
        if not os.path.exists(filepath1) and not os.path.exists(filepath2):
            c.execute('DELETE FROM files WHERE id = ?', (file_id,))
    conn.commit()
    
    c.execute('SELECT id, original_filename, upload_date FROM files WHERE user_id = ? ORDER BY upload_date DESC',
             (session['user_id'],))
    files = c.fetchall()
    conn.close()
    
    return render_template('dashboard.html', files=files, username=session['username'])

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected!', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected!', 'error')
        return redirect(url_for('dashboard'))
    
    if file:
        original_filename = secure_filename(file.filename)
        filename = f"{session['user_id']}_{os.urandom(8).hex()}_{original_filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)
        
        if not os.path.exists(filepath):
            flash('Error: File could not be saved!', 'error')
            return redirect(url_for('dashboard'))
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('INSERT INTO files (user_id, filename, original_filename) VALUES (?, ?, ?)',
                 (session['user_id'], filename, original_filename))
        conn.commit()
        conn.close()
        
        flash('File uploaded successfully!', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT filename, original_filename FROM files WHERE id = ? AND user_id = ?',
             (file_id, session['user_id']))
    file_data = c.fetchone()
    conn.close()
    
    if file_data:
        # Check both folders
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_data[0])
        if not os.path.exists(filepath):
            filepath = os.path.join(app.config['EDITED_PDF_FOLDER'], file_data[0])
        
        if os.path.exists(filepath):
            # This is the line 155 referenced in the traceback.
            # The logic is correct, the change here is ensuring dependencies are up-to-date.
            return send_file(filepath, as_attachment=True, download_name=file_data[1])
        else:
            flash('Error: File not found on server!', 'error')
            return redirect(url_for('dashboard'))
    else:
        flash('File not found!', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT filename FROM files WHERE id = ? AND user_id = ?',
             (file_id, session['user_id']))
    file_data = c.fetchone()
    
    if file_data:
        # Check both folders
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_data[0])
        if os.path.exists(filepath):
            os.remove(filepath)
        else:
            filepath = os.path.join(app.config['EDITED_PDF_FOLDER'], file_data[0])
            if os.path.exists(filepath):
                os.remove(filepath)
        
        c.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        flash('File deleted successfully!', 'success')
    else:
        flash('File not found!', 'error')
    
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', username=session['username'])

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    data = request.get_json()
    message = data.get('message', '').strip()
    
    if message:
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('INSERT INTO messages (user_id, username, message) VALUES (?, ?, ?)',
                 (session['user_id'], session['username'], message))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Message is empty'})

@app.route('/get_messages')
@login_required
def get_messages():
    since_id = request.args.get('since_id', 0, type=int)
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT id, username, message, timestamp FROM messages WHERE id > ? ORDER BY id ASC LIMIT 50',
             (since_id,))
    messages = c.fetchall()
    conn.close()
    
    result = []
    for msg in messages:
        result.append({
            'id': msg[0],
            'username': msg[1],
            'message': msg[2],
            'timestamp': msg[3]
        })
    
    return jsonify(result)

def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_IMAGE_EXTENSIONS']

@app.route('/image-to-pdf')
@login_required
def image_to_pdf_page():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT id, original_name, image_count, created_date FROM pdfs WHERE user_id = ? ORDER BY created_date DESC',
             (session['user_id'],))
    pdfs = c.fetchall()
    conn.close()
    
    return render_template('image_to_pdf.html', pdfs=pdfs, username=session['username'])

@app.route('/convert-images-to-pdf', methods=['POST'])
@login_required
def convert_images_to_pdf():
    if 'images' not in request.files:
        flash('No images selected!', 'error')
        return redirect(url_for('image_to_pdf_page'))
    
    files = request.files.getlist('images')
    
    if not files or all(f.filename == '' for f in files):
        flash('No images selected!', 'error')
        return redirect(url_for('image_to_pdf_page'))
    
    valid_files = [f for f in files if f and allowed_image_file(f.filename)]
    
    if not valid_files:
        flash('No valid image files! Please upload PNG, JPG, JPEG, GIF, BMP, or WEBP files.', 'error')
        return redirect(url_for('image_to_pdf_page'))
    
    try:
        image_list = []
        for file in valid_files:
            img = Image.open(file.stream)
            if img.mode in ('RGBA', 'LA', 'P'):
                rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                if img.mode == 'P':
                    img = img.convert('RGBA')
                rgb_img.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
                img = rgb_img
            elif img.mode != 'RGB':
                img = img.convert('RGB')
            image_list.append(img)
        
        if not image_list:
            flash('Could not process any images!', 'error')
            return redirect(url_for('image_to_pdf_page'))
        
        pdf_name = request.form.get('pdf_name', 'converted').strip()
        if not pdf_name:
            pdf_name = 'converted'
        pdf_name = secure_filename(pdf_name)
        filename = f"{session['user_id']}_{os.urandom(8).hex()}_{pdf_name}.pdf"
        filepath = os.path.join(app.config['PDF_FOLDER'], filename)
        
        image_list[0].save(filepath, save_all=True, append_images=image_list[1:], resolution=100.0, quality=95)
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('INSERT INTO pdfs (user_id, filename, original_name, image_count) VALUES (?, ?, ?, ?)',
                 (session['user_id'], filename, f"{pdf_name}.pdf", len(image_list)))
        conn.commit()
        conn.close()
        
        flash(f'Successfully converted {len(image_list)} images to PDF!', 'success')
    except Exception as e:
        flash(f'Error converting images: {str(e)}', 'error')
    
    return redirect(url_for('image_to_pdf_page'))

@app.route('/download-pdf/<int:pdf_id>')
@login_required
def download_pdf(pdf_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT filename, original_name FROM pdfs WHERE id = ? AND user_id = ?',
             (pdf_id, session['user_id']))
    pdf_data = c.fetchone()
    conn.close()
    
    if pdf_data:
        filepath = os.path.join(app.config['PDF_FOLDER'], pdf_data[0])
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=pdf_data[1])
        else:
            flash('Error: PDF not found on server!', 'error')
            return redirect(url_for('image_to_pdf_page'))
    else:
        flash('PDF not found!', 'error')
        return redirect(url_for('image_to_pdf_page'))

@app.route('/delete-pdf/<int:pdf_id>')
@login_required
def delete_pdf(pdf_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT filename FROM pdfs WHERE id = ? AND user_id = ?',
             (pdf_id, session['user_id']))
    pdf_data = c.fetchone()
    
    if pdf_data:
        filepath = os.path.join(app.config['PDF_FOLDER'], pdf_data[0])
        if os.path.exists(filepath):
            os.remove(filepath)
        c.execute('DELETE FROM pdfs WHERE id = ?', (pdf_id,))
        conn.commit()
        flash('PDF deleted successfully!', 'success')
    else:
        flash('PDF not found!', 'error')
    
    conn.close()
    return redirect(url_for('image_to_pdf_page'))

@app.route('/pdf-editor')
@login_required
def pdf_editor():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    c.execute('SELECT id, original_filename FROM files WHERE user_id = ? AND original_filename LIKE "%.pdf" ORDER BY upload_date DESC',
             (session['user_id'],))
    uploaded_pdfs = [{'id': f[0], 'name': f[1], 'type': 'file'} for f in c.fetchall()]
    
    c.execute('SELECT id, original_name FROM pdfs WHERE user_id = ? ORDER BY created_date DESC',
             (session['user_id'],))
    converted_pdfs = [{'id': p[0], 'name': p[1], 'type': 'pdf'} for p in c.fetchall()]
    
    conn.close()
    
    all_pdfs = uploaded_pdfs + converted_pdfs
    
    return render_template('pdf_editor.html', pdfs=all_pdfs, username=session['username'])

@app.route('/get-pdf-for-edit/<pdf_type>/<int:pdf_id>')
@login_required
def get_pdf_for_edit(pdf_type, pdf_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    if pdf_type == 'file':
        c.execute('SELECT filename FROM files WHERE id = ? AND user_id = ?',
                 (pdf_id, session['user_id']))
        result = c.fetchone()
        if result:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], result[0])
        else:
            conn.close()
            return jsonify({'error': 'PDF not found'}), 404
    else:
        c.execute('SELECT filename FROM pdfs WHERE id = ? AND user_id = ?',
                 (pdf_id, session['user_id']))
        result = c.fetchone()
        if result:
            filepath = os.path.join(app.config['PDF_FOLDER'], result[0])
        else:
            conn.close()
            return jsonify({'error': 'PDF not found'}), 404
    
    conn.close()
    
    if os.path.exists(filepath):
        try:
            reader = PdfReader(filepath)
            return jsonify({
                'success': True,
                'pages': len(reader.pages),
                'pdf_id': pdf_id,
                'pdf_type': pdf_type
            })
        except Exception as e:
            return jsonify({'error': f'Error reading PDF: {str(e)}'}), 500
    else:
        return jsonify({'error': 'PDF file not found on server'}), 404

@app.route('/edit-pdf', methods=['POST'])
@login_required
def edit_pdf():
    try:
        data = request.get_json()
        pdf_id = data.get('pdf_id')
        pdf_type = data.get('pdf_type')
        edits = data.get('edits', [])
        
        if not pdf_id or not pdf_type:
            return jsonify({'error': 'Missing PDF information'}), 400
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        
        if pdf_type == 'file':
            c.execute('SELECT filename, original_filename FROM files WHERE id = ? AND user_id = ?',
                     (pdf_id, session['user_id']))
            result = c.fetchone()
            if result:
                original_path = os.path.join(app.config['UPLOAD_FOLDER'], result[0])
                original_name = result[1]
            else:
                conn.close()
                return jsonify({'error': 'PDF not found'}), 404
        else:
            c.execute('SELECT filename, original_name FROM pdfs WHERE id = ? AND user_id = ?',
                     (pdf_id, session['user_id']))
            result = c.fetchone()
            if result:
                original_path = os.path.join(app.config['PDF_FOLDER'], result[0])
                original_name = result[1]
            else:
                conn.close()
                return jsonify({'error': 'PDF not found'}), 404
        
        if not os.path.exists(original_path):
            conn.close()
            return jsonify({'error': 'PDF file not found'}), 404
        
        reader = PdfReader(original_path)
        writer = PdfWriter()
        
        for page_num in range(len(reader.pages)):
            page = reader.pages[page_num]
            # Coordinates in reportlab are measured from the bottom-left,
            # so using `page.mediabox` is usually better for page sizing.
            # Using `letter` is fine if all documents are expected to be letter-sized.
            page_edits = [e for e in edits if e.get('page') == page_num]
            
            if page_edits:
                packet = io.BytesIO()
                can = canvas.Canvas(packet, pagesize=letter)
                
                for edit in page_edits:
                    if edit['type'] == 'text':
                        can.setFont("Helvetica", int(edit.get('fontSize', 12)))
                        can.drawString(float(edit['x']), float(edit['y']), edit['text'])
                
                can.save()
                packet.seek(0)
                overlay_pdf = PdfReader(packet)
                page.merge_page(overlay_pdf.pages[0])
            
            writer.add_page(page)
        
        edited_name = f"edited_{original_name}"
        filename = f"{session['user_id']}_{os.urandom(8).hex()}_{secure_filename(edited_name)}"
        output_path = os.path.join(app.config['EDITED_PDF_FOLDER'], filename)
        
        with open(output_path, 'wb') as output_file:
            writer.write(output_file)
        
        c.execute('INSERT INTO files (user_id, filename, original_filename) VALUES (?, ?, ?)',
                 (session['user_id'], filename, edited_name))
        conn.commit()
        new_id = c.lastrowid
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'PDF edited successfully!',
            'download_url': url_for('download_file', file_id=new_id)
        })
        
    except Exception as e:
        return jsonify({'error': f'Error editing PDF: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)