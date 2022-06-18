###############################
# Gunicorn configuration file #
###############################

import app
import statics

# Map hooks
on_starting = app.on_starting
on_reload = app.on_reload
post_worker_init = app.post_worker_init
on_exit = app.on_exit
worker_exit = app.worker_exit
when_ready = app.when_ready


# Set bind address and port
bind = "0.0.0.0:5000"

# Configure logs
loglevel = "debug"
accesslog = "-"
# Log format https://stackoverflow.com/questions/25737589/gunicorn-doesnt-log-real-ip-from-nginx
# TODO: determine if updates are necessary for this log format based on nginx headers
access_log_format = "%(h)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\" \"%({X-Real-IP}i)s\""
errorlog = "-"
keepalive = 5

# Set application directory
chdir = APP_SOURCE_PATH

# Preload the app to save memory and improve startup time
preload_app = True

# Use async libraries
worker_class = "gevent"
worker_connections = 1000

wsgi = app
# Number of workers and proxy will be appended to the file dynamically on startup by init.py