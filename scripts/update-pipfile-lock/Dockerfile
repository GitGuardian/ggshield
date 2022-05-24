FROM python:3.7

ARG UID

RUN pip install pipenv==2022.5.2
RUN useradd --uid $UID --create-home user

WORKDIR /home/user/src

CMD ["pipenv", "--python", "3.7", "lock"]
