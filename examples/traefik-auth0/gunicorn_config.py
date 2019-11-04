import multiprocessing
import gunicorn

gunicorn.SERVER_SOFTWARE = 'Traefik-Auth0'

worker_class = 'gevent'
log_level = 'INFO'
bind = "0.0.0.0:5000"
workers = 1  # multiprocessing.cpu_count() * 2 + 1
