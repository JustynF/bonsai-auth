import os.path


# Store shared statics here without crazy dependencies, so they can be imported outside the module
APP_VERSION = "0.0.0"
APP_ROOT_PATH = "/app"
APP_DATA_PATH = os.path.join(APP_ROOT_PATH, "data")
APP_SOURCE_PATH = os.path.join(APP_ROOT_PATH, "src")
FLASK_CONFIG_PATH = os.path.join(APP_SOURCE_PATH, "flask.config.py")
GUNICORN_CONFIG_PATH = os.path.join(APP_SOURCE_PATH, "gunicorn.conf.py")
JSON_CONFIG_PATH = os.path.join(APP_DATA_PATH, "config.json")
DEFAULT_SSH_CONFIG_DIR = "/etc/ssh"
DEFAULT_SSH_GROUP_CONFIG_DIR = os.path.join(DEFAULT_SSH_CONFIG_DIR, "sshd_config.d")
SSH_CONFIG_DIR = os.path.join(APP_DATA_PATH, "ssh")  # This is also used in the supervisor config for sshd
SSH_AUTHORIZED_KEYS_DIR = os.path.join(SSH_CONFIG_DIR, "authorized_keys")
SSH_GROUP_CONFIG_DIR = os.path.join(SSH_CONFIG_DIR, "sshd_config.d")
SSH_HOST_KEY_FILES = ["ssh_host_dsa_key", "ssh_host_dsa_key.pub", "ssh_host_ecdsa_key", "ssh_host_ecdsa_key.pub",
                      "ssh_host_ed25519_key", "ssh_host_ed25519_key.pub", "ssh_host_rsa_key", "ssh_host_rsa_key.pub"]
SSHD_CONFIG_PATH = os.path.join(SSH_CONFIG_DIR, "sshd_config")
USER_TYPES = ["admin", "basic"]  # TODO: Rename to builtin types? User created groups should be in the database
