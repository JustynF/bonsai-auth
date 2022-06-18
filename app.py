import logging
import os
import config
from api import api
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_session import Session, SqlAlchemySessionInterface
from flask_sqlalchemy import SQLAlchemy
from flask import Flask

from custom_logs import log


logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s]: {} %(levelname)s %(message)s'.format(os.getpid()),
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[logging.StreamHandler()])

logger = logging.getLogger()

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
sess = Session()
jwt = JWTManager()

def create_app():
    logger.info(f'Starting app in {config.APP_ENV} environment')
    global db, jwt, login_manager, migrate, sess
    app = Flask(__name__)
    app.config.from_pyfile('flask.config.py')
    api.init_app(app)
    # initialize SQLAlchemy
    db.init_app(app)
    #Alembic DB mirations
    migrate = Migrate(app,db)
    # Initialize login manager
    login_manager.session_protection = "strong"
    login_manager.init_app(app)

    # Initialize JWT authentication
    jwt.init_app(app)
    # Initialize flask_session
    sess.init_app(app)

    CORS(app)

    with app.app_context():
        # Include routes and models into the context
        import routes
        import models
        import routes
        # Set up the session interface
        SqlAlchemySessionInterface(app=app, db=db, table="sessions", key_prefix="bonsai_session_")
        return app


##################
# Gunicorn hooks #
##################

def on_starting(server):
    log.info("Starting Gunicorn server")


def on_reload(server):
    log.info("Gunicorn server has reloaded")


def post_worker_init(worker):
    log.info(f"Gunicorn worker initialized with pid: {worker.pid}")


def on_exit(server):
    log.info("Gunicorn server has quit")


def worker_exit(server, worker):
    log.info(f"Gunicorn worker has quit with pid: {worker.pid}")


def when_ready(server):
    log.info("Gunicorn server is ready")


if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0',port="6969",debug=True)
