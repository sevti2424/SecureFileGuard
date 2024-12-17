from flask import Flask
from config import Config
from routes import main_bp

app = Flask(__name__)
app.config.from_object(Config)

# Register blueprints
app.register_blueprint(main_bp, url_prefix='/')

if __name__ == '__main__':
    app.run(debug=True)