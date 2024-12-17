import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
    SECRET_KEY = 'your-secret-key-here'
class Config:
    SECRET_KEY = 'your_secret_key'  # Secure key for sessions
    MYSQL_HOST = 'your_mysql_host'
    MYSQL_USER = 'your_mysql_user'
    MYSQL_PASSWORD = 'your_mysql_password'
    MYSQL_DB = 'your_database_name'
