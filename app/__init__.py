# No arquivo app/__init__.py

from flask import Flask

def create_app():
    app = Flask(__name__)

    # <-- A LINHA QUE RESOLVE O PROBLEMA ESTÁ AQUI
    # Esta chave secreta é necessária para a 'session' (e o download) funcionar.
    app.config['SECRET_KEY'] = 'pode-ser-qualquer-texto-longo-e-secreto-aqui'

    # Suas outras configurações, se tiver...
    # Ex: app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

    from . import routes
    app.register_blueprint(routes.bp)

    return app