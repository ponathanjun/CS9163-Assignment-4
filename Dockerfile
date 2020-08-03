FROM python:3.5.6

MAINTAINER Jonathan Pun "jp5474@nyu.edu"

COPY ./requirements.txt /app/requirements.txt

WORKDIR /app

RUN pip install -r requirements.txt

COPY . /app

CMD flask run --host=0.0.0.0 --port=8080
