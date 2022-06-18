import uuid
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from app import db


class User(UserMixin, db.Model):
    """Store api users
    """
    # table name usually defaults to the model name
    __tablename__ = "bonsai_users"

    # Define table columns
    id = db.Column(db.Integer, primary_key=True,
                   comment="Unique DB-generated user ID")
    username = db.Column(db.VARCHAR(length=32), nullable=False, unique=True,
                         comment="Unique username")
    email = db.Column(db.Text, nullable=True, unique=True,
                      comment="Unique email address")
    password = db.Column(db.VARCHAR(length=88), nullable=True, unique=False,
                         comment="Hashed user password")
    legacy_password = db.Column(db.Text, nullable=True, unique=False,
                                comment="Legacy password (a line from /etc/shadow)")
    type = db.Column(db.Text, nullable=False,
                     comment="User type")
    added_on = db.Column(db.DateTime, nullable=False, unique=False,
                         comment="User creation timestamp")
    last_login = db.Column(db.DateTime, nullable=True, unique=False,
                           comment="Last login timestamp")

    def set_password(self, password):
            """Create hashed password."""
            self.password = generate_password_hash(password, method="sha256")
            self.legacy_password = None


    def check_password(self, password):
        """Check hashed password."""
        if self.legacy_password is not None:
            # TODO: Parse the field and process it
            # https://www.cyberciti.biz/faq/understanding-etcshadow-file/
            # https://manpages.debian.org/unstable/libcrypt-dev/crypt.5.en.html#AVAILABLE_HASHING_METHODS
            # testguy:$y$j9T$x7o4Uelp5A4yZIK19DvoS/$6Y8E.laRvLIm2GGngURPsqvv7CYAwxig1cWD7FHEsAA:19107:0:99999:7:::
            # basicboi:!:19108:0:99999:7:::
            # username:$1$TrOIigLp$PUHL00kS5UY3CMVaiC0/g0:15020:0:99999:7:::
            # openssl passwd -1 -salt TrOIigLp
            pass
        return check_password_hash(self.password, password)

class UserKey(db.Model):
    """Store users' public keys
    """
    __tablename__ = "api_user_keys"

    # TODO: Change to UUID
    id = db.Column(db.Integer, primary_key=True,
                   comment="Unique DB-generated key ID")
    api_user_id = db.Column(db.Integer, db.ForeignKey("api_users.id"), nullable=False,
                            comment="Matches an id in the api_users table")
    key = db.Column(db.VARCHAR(length=32768), nullable=False, unique=False,
                    comment="One authorized key")
    added_on = db.Column(db.DateTime, nullable=False, unique=False,
                         comment="Key addition timestamp")

    def __repr__(self):
        return f"Key: id={self.id}, key={self.key}"

class UserToken(db.Model):
    """Store information about users' API tokens
    """
    __tablename__ = "api_user_tokens"

    id = db.Column(db.VARCHAR(length=36), primary_key=True,
                   comment="Token UUID")
    api_user_id = db.Column(db.Integer, db.ForeignKey("api_users.id"), nullable=False,
                            comment="Token owner, matches an id in the api_users table")
    added_on = db.Column(db.DateTime, nullable=False, unique=False,
                         comment="Creation timestamp")
    valid = db.Column(db.Boolean, nullable=False,
                      comment="If false, the token cannot be used")
    expiry = db.Column(db.DateTime, nullable=True, unique=False,
                       comment="Expiry timestamp")

    def __repr__(self):
        return f"Key: id={self.id}, key={self.key}"