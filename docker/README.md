# django_simplify Docker version
Script to create a basic Django site docker image 

Push this image on your dockerhub account

Launch a django site with daphne listening on port 80, with a volume mounted for /var/www/django with the code and the venv to simple editing out of container

# Create your own docker
## Requirements (optional)
- dockerhub account
- precreated repository on dockerhub named django_simplify
## Commands
- cd /tmp
- git clone https://github.com/lucapiccio/django_simplify.git
- chmod +x django_simplify/docker/make-docker.sh
- cd django_simplify/docker
- sudo ./make-docker.sh

# Standard Using
- docker pull swipon/simpledjango:latest
- docker volume create django-simplify-volume
- docker run -d --name django-simplify -p 80:80 -v django-simplify-volume:/var/www/django django-simplify

## Edit django
- cd $(docker volume inspect django-simplify-volume | grep Mountpoint | awk '{print $2}' | cut -d\" -f2)
- make your modification

### Make collect static + makemigration + migrate
- docker exec -it django-simplify ./build.sh

## Exec some commands inside the docker
- docker exec -it django-simplify /bin/bash
- source bin/activate
- launch your command
