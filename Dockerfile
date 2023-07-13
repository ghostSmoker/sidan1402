# base image
FROM python:3.9.10

# options
ENV PYTHONUNBUFFERED 1

# Set working directory
RUN mkdir core
# set the working directory
COPY . /core/
# coppy commands
WORKDIR /core

# update docker-iamage packages
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y netcat-openbsd gcc && \
    apt-get clean

# update pip
#RUN pip install --upgrade pip
# install psycopg for connect to pgsql
RUN pip install psycopg2-binary
# install python packages
RUN pip install -r requirements.txt
# create static directory
RUN mkdir static
#RUN python manage.py runserver
EXPOSE 8080
CMD ["gunicorn","--bind", ":8080", "app.wsgi:application"]