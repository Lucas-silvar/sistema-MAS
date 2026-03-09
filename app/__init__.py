
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
    app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # JavaScript não pode acessar
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutos de inatividade
    app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

    limiter.init_app(app)

    from . import routes
    app.register_blueprint(routes.bp)

    return app