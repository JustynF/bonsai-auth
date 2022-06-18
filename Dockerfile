FROM python:3.9

RUN pip install pipenv

ADD . /flask-deploy

WORKDIR /flask-deploy

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
RUN pipenv install --system --skip-lock
RUN pip install --upgrade pip
RUN pip install gunicorn[gevent]
EXPOSE 5000

CMD gunicorn --worker-class gevent --workers 8 --bind 0.0.0.0:5000 wsgi:app --max-requests 10000 --timeout 5 --keep-alive 5 --log-level info