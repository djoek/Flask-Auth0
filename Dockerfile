FROM python:3.7

MAINTAINER flask-auth0@djoek.net

RUN pip install --no-cache python-dotenv flask gunicorn gevent requests pycryptodome python-jose[pycryptodome] cachelib

COPY flask_auth0 /tmp/Flask-Auth0/flask_auth0
COPY setup.py /tmp/Flask-Auth0/setup.py
RUN pip install --no-cache /tmp/Flask-Auth0

COPY examples /usr/src/app
WORKDIR /usr/src/app/traefik-auth0


EXPOSE 5000

ENTRYPOINT ["gunicorn", "-c",  "/usr/src/app/traefik-auth0/gunicorn_config.py", "--forwarded-allow-ips=\"*\""]
CMD ["main:app"]
