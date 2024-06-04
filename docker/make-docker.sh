#!/bin/bash

apt -y -q install docker docker-compose docker.io
read -p "Enter your docker login username:" dockerusername
docker login --username $dockerusername

cat <<EOF > .dockerignore
./pyvenv.cfg
.venv
EOF

cat <<EOF > Dockerfile
FROM python:3.11
ENV PYTHONUNBUFFERED 1
RUN mkdir /app
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app/
EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
EOF

cat <<EOF > docker-compose.yml
version: '3.8'

services:
  my-postgres:
    image: postgres:15
    container_name: db
    environment:
     - POSTGRES_DB=
     - POSTGRES_USER=
     - POSTGRES_PASSWORD=
    ports:
    - '5432:5432'
    volumes:
    - pg_data:/var/lib/postgresql/data

  web:
    build: .
    container_name: django
    ports:
      - '8000:8000'
    volumes:
      - .:/app
    environment:
      - DJANGO_ENV=
      - DATABASE_NAME=
      - DATABASE_USER=
      - DATABASE_PASSWORD=
      - DATABASE_HOST=
      - DATABASE_PORT=
    depends_on:
      - my-postgres

volumes:
  pg_data:
EOF

docker build -t django-bootstrap-app .
docker network create my-django-postgres-network
docker run --name my-postgres -p 5432:5432 -e POSTGRES_USER=<your_postgres_user> -e POSTGRES_PASSWORD=<your_posgres_user_password> --network my-django-postgres-network -d postgres
docker --env-file .env run --name django-bootstrap-app-c1 -p 8000:8000 --network my-django-postgres-network -d django-bootstrap-app
docker exec -it django-bootstrap-app-c1 python manage.py migrate
docker tag django-bootstrap-app $dockerusername/django-bootstrap-app
docker push $dockerusername/django-bootstrap-app
docker pull $dockerusername/django-bootstrap-app

