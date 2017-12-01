FROM python:3.7

MAINTAINER flask-auth0@djoek.net

RUN pip install python-dotenv flask requests pycryptodome python-jose[pycryptodome]

COPY flask_auth0 /tmp/Flask-Auth0/flask_auth0
COPY setup.py /tmp/Flask-Auth0/setup.py
RUN pip install /tmp/Flask-Auth0

COPY examples /usr/src/app
WORKDIR /usr/src/app

ENV FLASK_APP main.py

EXPOSE 5000

CMD flask run --host 0.0.0.0