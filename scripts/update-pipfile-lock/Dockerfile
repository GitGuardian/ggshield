FROM python:3.7

ARG UID

RUN pip install pipenv
RUN useradd --uid $UID --create-home user

WORKDIR /home/user/src

CMD ["pipenv", "lock"]
