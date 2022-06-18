import os.path


# Flask-JWT-Extended
JWT_TOKEN_LOCATION = ["headers"]
JWT_ACCESS_TOKEN_EXPIRES = 7776000  # Tokens last at most for this long (90 days) before requiring a refresh
JWT_ALGORITHM = "HS256"
JWT_DECODE_LEEWAY = 2  # Allow for a few seconds of clock drift when decoding JWTs
JWT_IDENTITY_CLAIM = "sub"  # Store the user ID in the entry called 'sub' i.e. Subject
JWT_ERROR_MESSAGE_KEY = "msg"
JWT_HEADER_NAME = "Authorization"
JWT_HEADER_TYPE = "Bearer"

# Flask-Login
# https://flask-login.readthedocs.io/en/latest/#cookie-settings
REMEMBER_COOKIE_REFRESH_EACH_REQUEST = True
REMEMBER_COOKIE_DURATION = 7776000

# General flask session configuration
# https://flask.palletsprojects.com/en/2.1.x/config/#SESSION_REFRESH_EACH_REQUEST
PERMANENT_SESSION_LIFETIME = 7776000  # Sessions last for at most 90 days before requiring re-authentication
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_NAME = "bonsai_session"
# SESSION_COOKIE_SECURE = True
SESSION_REFRESH_EACH_REQUEST = True

# Flask-Session
SESSION_PERMANENT = True
SESSION_TYPE = "sqlalchemy"  # Store sessions in the database
SESSION_USE_SIGNER = True  # Require secret_key

# Set domain for security and subdomain support
# SERVER_NAME = "domain.com"

# Keep json in unicode
JSON_AS_ASCII = False

# Overwritten at runtime
SECRET_KEY = 'BarnabusPlusGreenVamp'
