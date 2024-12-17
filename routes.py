from flask import Blueprint, render_template, request, send_file, flash, redirect, url_for, current_app
import os
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from utils.file_handler import allowed_file, save_uploaded_file
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad




main_bp = Blueprint('main', __name__)



ALLOWED_ENCRYPTED_EXTENSIONS = {'enc'}
ALLOWED_KEY_EXTENSIONS = {'key'}

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions



# Get the upload folder dynamically
def get_upload_folder():
    return os.path.join(current_app.root_path, 'uploads')

# Ensure the upload folder exists
def ensure_upload_folder():
    upload_folder = get_upload_folder()
    if not os.path.exists(upload_folder):
        print(f"Creating upload folder: {upload_folder}")
        os.makedirs(upload_folder)
    else:
        print(f"Upload folder exists: {upload_folder}")

def generate_key():
    # AES key should be either 16, 24, or 32 bytes long
    key = os.urandom(16)  # Generate a 256-bit key (32 bytes)
    return key

def encrypt_file(filepath, key):
    encrypted_filename = f'encrypted_{os.path.basename(filepath)}'  # Prefix with 'encrypted_'
    encrypted_filepath = os.path.join(os.path.dirname(filepath), encrypted_filename)
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Pad data to be multiple of AES block size (16 bytes)
    padder = padding.PKCS7(128).padder()  # AES block size is 128 bits (16 bytes)
    padded_data = padder.update(data) + padder.finalize()

    # Generate a random 16-byte IV (Initialization Vector) for CBC mode
    iv = os.urandom(16)

    # Create the cipher object for AES CBC encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Perform encryption
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the IV and encrypted data to the file
    with open(encrypted_filepath, 'wb') as f:
        f.write(iv)  # Prepend the IV to the encrypted data (necessary for decryption)
        f.write(encrypted_data)

    return encrypted_filepath  # Return the path of the encrypted file

def adjust_key_length(key, length):
    # Pastikan kunci memiliki panjang yang sesuai dengan ukuran yang dibutuhkan
    if isinstance(key, str):
        key = key.encode('utf-8')  # Ubah key ke byte jika berupa string
    return key.ljust(length, b'\0')[:length]  # Sesuaikan panjang kunci dengan padding atau pemotongan

def decrypt_file(encrypted_filepath, key):
    # Pastikan kunci memiliki panjang 16 byte untuk AES-128
    key = adjust_key_length(key, 16)  # Sesuaikan panjang kunci menjadi 16 byte
    
    # Baca file terenkripsi
    with open(encrypted_filepath, 'rb') as f:
        encrypted_data = f.read()

    # Inisialisasi IV (Initialization Vector) yang mungkin disertakan di bagian awal data
    iv = encrypted_data[:AES.block_size]  # Biasanya IV ada di bagian depan
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Dekripsi dan hapus padding
    decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)

    # Simpan hasil dekripsi ke file baru
    decrypted_filepath = encrypted_filepath.replace('.enc', '.dec')
    with open(decrypted_filepath, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_filepath
@main_bp.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(url_for('main.index'))

        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(url_for('main.index'))

        try:
            ensure_upload_folder()

            # Save uploaded file
            filename = secure_filename(file.filename)
            filepath = save_uploaded_file(file, filename)

            # Generate encryption key
            key = generate_key()

            # Save encryption key to file
            key_filename = f'{filename}.key'
            key_filepath = os.path.join(get_upload_folder(), key_filename)
            with open(key_filepath, 'wb') as key_file:
                key_file.write(key)

            # Encrypt the file
            encrypted_filepath = encrypt_file(filepath, key)

            # Return the encrypted file and key file to the template
            return render_template(
                'encrypted.html',
                encrypted_file=os.path.basename(encrypted_filepath),
                key_file=key_filename  # Pass the key file to the template
            )
        except Exception as e:
            print(f"Encryption failed: {e}")
            flash(f'Encryption failed: {str(e)}')
            return redirect(url_for('main.index'))
    return render_template('encrypted.html')






@main_bp.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'GET':
        # Menampilkan halaman dekripsi kosong
        return render_template('decrypt.html')

    if request.method == 'POST':
        # Debug: Log incoming request files
        print(f"Request files: {request.files}")

        # Memeriksa apakah file terenkripsi dan file kunci ada dalam request.files
        if 'file' not in request.files or 'key_file' not in request.files:
            flash('Please upload both the encrypted file and the key file.')
            return redirect(url_for('main.index'))

        encrypted_file = request.files['file']
        key_file = request.files['key_file']

        # Memeriksa apakah nama file tersedia
        if encrypted_file.filename == '' or key_file.filename == '':
            flash('No file selected for decryption.')
            return redirect(url_for('main.index'))

        try:
            # Menyimpan file secara lokal
            encrypted_filename = secure_filename(encrypted_file.filename)
            key_filename = secure_filename(key_file.filename)

            encrypted_filepath = save_uploaded_file(encrypted_file, encrypted_filename)
            key_filepath = save_uploaded_file(key_file, key_filename)

            # Membaca kunci enkripsi dari file kunci
            with open(key_filepath, 'rb') as kf:
                key = kf.read()

            # Mendekripsi file terenkripsi menggunakan kunci
            decrypted_filepath = decrypt_file(encrypted_filepath, key)
            # Mendefinisikan nama baru untuk file yang didekripsi
            decrypted_filename = f'decryp_{os.path.basename(decrypted_filepath)}'

            # Menampilkan file terdekripsi
            return render_template('decrypt.html', decrypted_file=decrypted_filename)

        except Exception as e:
            flash(f'Decryption failed: {str(e)}')
            return redirect(url_for('main.index'))





@main_bp.route('/download/encrypted/<filename>', methods=['GET'])
def download_encrypted_file(filename):
    try:
        upload_folder = get_upload_folder()
        encrypted_filepath = os.path.join(upload_folder, filename)

        if not os.path.exists(encrypted_filepath):
            flash('Encrypted file not found')
            return redirect(url_for('main.index'))

        return send_file(
            encrypted_filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        flash('An error occurred while trying to download the encrypted file')
        return redirect(url_for('main.index'))


@main_bp.route('/download/key/<filename>', methods=['GET'])
def download_key_file(filename):
    try:
        upload_folder = get_upload_folder()
        key_filepath = os.path.join(upload_folder, filename)
        
        if not os.path.exists(key_filepath):
            flash('Key file not found')
            return redirect(url_for('main.index'))

        return send_file(
            key_filepath,
            as_attachment=True,
            download_name=f'{filename}.key',
            mimetype='application/octet-stream'
        )
    except Exception as e:
        flash('An error occurred while trying to download the key file')
        return redirect(url_for('main.index'))


@main_bp.route('/')
def index():
    return render_template('index.html')

def save_uploaded_file(file, filename):
    # Secure the filename to prevent directory traversal attacks
    filename = secure_filename(filename)  # Ensure the filename is safe
    # Define the path where you want to save the uploaded file
    filepath = os.path.join(get_upload_folder(), filename)  # Use dynamic upload folder
    file.save(filepath)  # Save the file
    return filepath

@main_bp.route('/refresh-key', methods=['POST'])
def refresh_key():
    try:
        # Hapus key atau file lama
        os.remove(os.path.join(get_upload_folder(), 'old_key.key'))  # Contoh menghapus key lama
        # Generate key baru
        new_key = generate_key()

        # Simpan key baru ke file
        new_key_filename = 'new_key.key'
        key_filepath = os.path.join(get_upload_folder(), new_key_filename)
        with open(key_filepath, 'wb') as key_file:
            key_file.write(new_key)

        # Beritahu pengguna bahwa key telah diperbarui
        flash('Key telah diperbarui! Anda dapat mengunduh key baru.')

        # Kembalikan ke halaman utama dengan info tentang key baru
        return render_template('index.html', key_file=new_key_filename)
    except Exception as e:
        flash(f'Terjadi kesalahan: {str(e)}')
        return redirect(url_for('main.index'))
def delete_old_files():
    # Hapus file key atau file lainnya jika diperlukan
    try:
        old_key_filepath = os.path.join(get_upload_folder(), 'old_key.key')
        if os.path.exists(old_key_filepath):
            os.remove(old_key_filepath)
    except Exception as e:
        print(f"Error deleting old files: {str(e)}")
@main_bp.route('/download_decrypted_file/<filename>')
def download_decrypted_file(filename):
    # Path file yang didekripsi
    file_path = os.path.join(get_upload_folder(), filename)
    
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True, download_name=filename)
    else:
        flash('File not found!')
        return redirect(url_for('main.index'))

