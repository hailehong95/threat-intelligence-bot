# FROM python:3.8-alpine
FROM ubuntu:20.04
WORKDIR /tibot
COPY requirements.txt /tibot
RUN apt update -y
RUN apt install -y build-essential libssl-dev libffi-dev python3 python3-dev python3-pip
RUN pip3 install -r requirements.txt --no-cache-dir
COPY . /tibot
ENTRYPOINT ["python3"]
CMD ["vt-telegram-bot.py"]
