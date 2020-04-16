FROM python:3.6

LABEL maintainer="support@gitguardian.com"

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

RUN pip install pipenv --upgrade

RUN useradd --create-home app
WORKDIR /home/app

COPY . .

RUN set -ex && pipenv install --system --ignore-pipfile

USER app

CMD [ "ggshield" ]

