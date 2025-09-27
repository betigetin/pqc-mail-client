# backend/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from .config import Config

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    CORS(app)

    # Register routes blueprint after db init
    from .routes import api as api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    # Create tables if not present (simple dev setup)
    with app.app_context():
        db.create_all()

    return app
