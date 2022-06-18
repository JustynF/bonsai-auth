import datetime
import os
import re
from email.utils import parseaddr

from flask import Response, request, redirect, session, jsonify
from flask import current_app as app
import flask_jwt_extended
from flask_jwt_extended import create_access_token
from flask_login import current_user, login_required, login_user, logout_user

from app import db, login_manager
from custom_logs import log
from models import User, UserKey
from statics import *


@app.before_first_request
def before_first_request_func():
    """This will run on each worker thread before the first request hits
    """
    log.info(f"Worker active with pid: {os.getpid()}")


@app.before_request
def basic_authentication():
    """Allow OPTIONS for CORS
    """
    if request.method.lower() == "options":
        return Response()


@app.before_request
def session_timeout():
    # Protect against replay attacks by invalidating sessions after 30 minutes
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=30)
    session.modified = True


@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
@app.route("/index", methods=["GET"])
def index():
    log.info("Home hit")
    return jsonify({"msg": "Hello World via HTTP"}), 200


@app.route("/api/v1/test", methods=["GET"])
def api_v1_test():
    log.info("API test hit")
    return jsonify({"msg": "API test hit"}), 200


@login_manager.request_loader
def load_user_from_request(r):
    """ If no cookie is provided, attempt validation with JWT.
    """
    log.info(f"Unable to authenticate with Cookie. Loading user from request: {r}")
    try:
        # Validate JWT in request
        data = flask_jwt_extended.verify_jwt_in_request()
        log.info(f"JWT data: {data}")
        # user = User.query.filter_by(id=request_data["sub"]).first()
        # if user is not None:
        #     print()
    except Exception as e:
        log.info(f"Unable to authenticate with JWT. Request: {request}, Error: {e}")
    # Unable to authenticate user
    return None


#######################
# User Authentication #
#######################

# TODO ADD CHANGE PASSWORD (WITH FRESH LOGIN REQUIRED)
# TODO ADD USER ABILITY TO REMOVE KEYS
# TODO ADD ADMIN ABILITY TO CHANGE ANY USER PASSWORD
# TODO ADD ADMIN ABILITY TO MANAGE ANY USER'S KEYS (ADD/REMOVE)
# TODO ADD ADMIN ABILITY TO MANAGE ANY USER'S TOKENS (GENERATE/REVOKE)

@app.route("/api/v1/auth/login", methods=["POST"])
def api_v1_auth_login():
    if current_user.is_authenticated:
        # return "Auth login already OK for " + current_user.username, 200
        return jsonify({"msg": "Auth login already OK"}), 200
    request_data = request.get_json(cache=False)
    if not request_data:
        log.error(f"Unable to decode request data as JSON")
        return jsonify({"msg": "Unable to decode `data` as valid JSON payload"}), 400
    user = User.query.filter_by(username=request_data["username"]).first()
    if user and user.check_password(password=request_data["password"]):
        # Log the user in
        login_user(user, remember=False, duration=datetime.timedelta(minutes=30))
        # Update their last_login time in the DB
        previous_login = user.last_login
        user.last_login = (datetime.datetime.now())
        db.session.add(user)
        db.session.commit()
        if previous_login is None:
            log.info(f"User logged in for the first time: {user}")
        else:
            log.info(f"User logged in: {user}. Previous login was {previous_login}")
        return jsonify({"msg": "Auth login OK"}), 200
    else:
        return jsonify({"msg": "Auth login invalid"}), 401


@app.route("/api/v1/auth/logout", methods=["POST"])
@login_required
def api_v1_auth_logout():
    # Capture current information before logging out user
    previous_login = str(current_user.last_login)
    user_string = str(current_user)
    # Log the user out
    # FIXME: Add a blacklist so the user can't log in using the token, if it was captured? i.e. prevent replay attacks
    logout_user()
    if previous_login is not None:
        log.info(f"User logged out: {user_string}. Previous login was {previous_login}")
    else:
        log.info(f"User logged out for the first time: {user_string}")
    return jsonify({"msg": "Auth logout OK"}), 200


@app.route("/api/v1/auth/keys/add", methods=["POST"])
@login_required
def api_v1_keys_add():
    """Add a new public key
    """
    request_data = request.get_json(cache=False, silent=True)
    if not request_data:
        log.error(f"Unable to decode request data as JSON")
        return jsonify({"msg": "Unable to decode `data` as valid JSON payload"}), 400
    if "key" not in request_data:
        return jsonify({"msg": "No `key` in json"}), 400
    # Keys should be a max of 16kb, so double that should be a reasonable limit here
    # https://www.freebsd.org/cgi/man.cgi?query=sshd
    if len(request_data["key"]) > 32768:
        return jsonify({"msg": "Key is suspiciously long"}), 400
    # Remove trailing spaces in the input
    clean_input_key = request_data["key"].rstrip()
    if "\n" in clean_input_key or "\r" in clean_input_key:
        return jsonify({"msg": "Key is formatted incorrectly or contains more than one entry"}), 400
    # Ensure the key does not already exist
    existing_key = UserKey.query.filter_by(api_user_id=current_user.id) \
        .filter_by(key=clean_input_key) \
        .first()
    if existing_key:
        return jsonify({"msg": "Key already added OK"}), 201
    # TODO: validate key is functional before adding?
    user_key = UserKey(api_user_id=current_user.id, key=clean_input_key, added_on=datetime.datetime.now())
    db.session.add(user_key)
    db.session.commit()
    log.info(f"New key with id {user_key.id} added for user {current_user.username}")
    return jsonify({"msg": "Key added OK"}), 201


@app.route("/api/v1/auth/keys/get", methods=["POST"])
@login_required
def api_v1_keys_get():
    """Get one or all public keys
    """
    request_data = request.get_json(cache=False, silent=True)
    if not request_data or "id" not in request_data:
        # Find all keys
        existing_keys = UserKey.query.filter_by(api_user_id=current_user.id).order_by(UserKey.id).all()
        if existing_keys:
            keys = []
            for existing_key in existing_keys:
                keys.append({"id": existing_key.id, "key": existing_key.key})
            return jsonify(keys), 200
        else:
            return jsonify({"msg": "No keys found"}), 400
    # Find a specific key
    try:
        key_id = int(request_data["id"])
    except Exception as e:
        log.info(f"Unable to decode key id from request: {request_data['id']}")
        return jsonify({"msg": "Unable to decode `id` as valid integer"}), 400
    # Filter on the user, so that users can't spam ids to find others' keys
    existing_key = UserKey.query.filter_by(id=key_id) \
        .filter_by(api_user_id=current_user.id) \
        .first()
    if existing_key:
        return jsonify({"key": existing_key.key}), 200
    else:
        return jsonify({"msg": "No matching key found"}), 400


@app.route("/api/v1/auth/tokens/add", methods=["POST"])
@login_required
def api_v1_tokens_add():
    """Add a new JWT
    """

    # TODO: WORK IN PROGRESS WIP HERE
    #   - If no arguments are provided, assume all defaults
    #   - Allow non-admins to create new tokens with valid lengths equal or less than the default
    #   - Allow non-admins to create up to 5 tokens
    #   - Allow admins to create tokens with any length, even no expiration time at all

    # TEST JWT CREATION
    access_token = create_access_token(identity=current_user.id)
    log.info(f"Encoded JWT: {access_token}")
    # <Response 281 bytes [200 OK]>
    log.info(f"Response encoded: {str(jsonify(token=access_token))}")
    # {'token': 'eyJ0eXAiOiJ..........eGoX8Ao'}
    log.info(f"Response JSON: {str(jsonify(token=access_token).get_json())}")
    # {'fresh': False, 'iat': 1653894938, 'jti': 'a4f82167-0a84-4196-b98d-f985045cffe6', 'type': 'access', 'sub': 1,
    # 'nbf': 1653894938, 'exp': 1653896738}
    log.info(f"Decoded JWT: {str(flask_jwt_extended.decode_token(access_token))}")

    # Validate user permissions
    if current_user.type != "admin":
        return jsonify(msg="Not allowed"), 401
    # Validate request format
    request_data = request.get_json(cache=False, silent=True)
    if not request_data:
        log.error(f"Unable to decode request data as JSON")
        return jsonify(msg="Unable to decode `data` as valid JSON payload"), 400
    # At minimum, should request the username (probably the user's own username, unless they are admin)
    if "user" not in request_data:
        return jsonify(msg="No `user` in json"), 400

    return jsonify(msg="blahblahblah"), 201


@app.route("/api/v1/auth/signup", methods=["POST"])
@login_required
def api_v1_auth_signup():
    """Signup API endpoint, restricted to admins.
    Expects "name", "password", and optionally "email" and "type"
    """
    # Validate user permissions
    if current_user.type != "admin":
        return jsonify({"msg": "Not allowed"}), 401
    # Validate request format
    request_data = request.get_json(cache=False, silent=True)
    if not request_data:
        log.error(f"Unable to decode request data as JSON")
        return jsonify({"msg": "Unable to decode request data as valid JSON payload"}), 400
    # Validate username
    if "username" not in request_data:
        return jsonify({"msg": "No username received"}), 400
    username = request_data["username"]
    # Ensure username is at most 32 characters long
    if len(username) > 32 or len(username) < 1:
        return jsonify({"msg": "Usernames must be 1-32 characters in length"}), 400
    # Ensure username does not start with a dash (otherwise dash is permitted)
    if username[0] == "-":
        return jsonify({"msg": "Usernames must not start with a dash/hyphen \"-\""}), 400
    # Usernames must contain only lowercase a-z, 0-9, underscore, and dash
    for char in username:
        if char.isspace():
            return jsonify({"msg": "Usernames must not contain whitespace"}), 400
    # Usernames can only contain one $ at the end, and no others
    if username.find('$', 0, len(username) - 1) != -1:
        return jsonify({"msg": "Usernames must not contain \"$\" anywhere except as the last character"}), 400
    # Validate username against all the rules in a single regular expression with explicit lowercase alphabet
    # https://unix.stackexchange.com/questions/157426/what-is-the-regex-to-validate-linux-users#157431
    validate_username_regex = "^[abcdefghijklmnopqrstuvwxyz_]" \
                              "([abcdefghijklmnopqrstuvwxyz0-9_-]{0,31}|[abcdefghijklmnopqrstuvwxyz0-9_-]{0,30}\\$)$"
    if not re.search(validate_username_regex, username):
        return jsonify({"msg": "Invalid username "}), 400
    existing_user = User.query.filter_by(username=username).first()
    if existing_user is not None:
        return jsonify({"msg": "Username already exists"}), 400
    # Validate password
    if "password" not in request_data:
        return jsonify({"msg": "No password received"}), 400
    password = request_data["password"]
    # TODO: Add configurable password parameters
    if len(password) < 8:
        return jsonify({"msg": "Password must be greater than 8 characters in length"}), 400
    elif len(password) >= 512:
        # Passwords longer than PAM_MAX_RESP_SIZE are not permitted due to PAM restrictions
        # TODO: determine if it's <512 or =512, I'm seeing conflicting information
        # https://bugzilla.redhat.com/show_bug.cgi?id=1934523
        # https://github.com/linux-pam/linux-pam/issues/59
        # TODO: patch pam to support 512+ octet passwords
        return jsonify({"msg": "Password must be less than 512 characters in length"}), 400
    # Validate email
    if "email" in request_data:
        email = request_data["email"]
        existing_user = User.query.filter_by(email=email).first()
        if existing_user is not None:
            return jsonify({"msg": "Email already exists"}), 400
        # if email is not properly formatted, this should fail https://docs.python.org/3/library/email.utils.html
        # TODO: send verification message
        if "@" not in parseaddr(email)[1]:
            return jsonify({"msg": "Invalid email"}), 400
    else:
        # Email is optional
        email = None
    if "type" in request_data:
        user_type = request_data["type"]
        if user_type not in USER_TYPES:
            return jsonify({"msg": "Invalid type", "types": USER_TYPES}), 400
    else:
        # type is optional
        user_type = "basic"
    # Create the user
    user = User(username=username, email=email, type=user_type, added_on=datetime.datetime.now())
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    log.info(f"User created: {user}")
    retrieve_user = User.query.filter_by(username=username).first()
    if retrieve_user is not None:
        return jsonify({"msg": "User created OK"}), 201
    else:
        log.error(f"Unable to retrieve user after creation: {user}")
        return jsonify({"msg": "Unable to confirm user creation"}), 500


@login_manager.user_loader
def load_user(user_id):
    """Check if user is logged-in upon page load."""
    if user_id is not None:
        return User.query.get(user_id)
    return None


@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to Login page."""
    return redirect("/api/v1/auth/login")
