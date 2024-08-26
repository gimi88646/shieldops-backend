FROM python:3.11.4-alpine

WORKDIR /usr/src/app

ENV PYTHONDONTWRITEBYTECODE 1 

ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip

COPY ./requirements.txt /usr/src/app/requirements.txt

RUN pip install -r requirements.txt

# COPY ./entrypoint.sh .

# RUN chmod +x ./entrypoint.sh

COPY ./mitrerules/* /usr/src/app/

# ENTRYPOINT [ "/usr/src/app/entrypoint.sh" ]