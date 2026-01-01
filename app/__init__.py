
from flask import Flask

def create_app():
    app = Flask(__name__)

    # Esta chave secreta é necessária para a 'session' (e o download) funcionar.
    app.config['SECRET_KEY'] = 'pode-ser-qualquer-texto-longo-e-secreto-aqui'
    app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

    from . import routes
    app.register_blueprint(routes.bp)

    return app