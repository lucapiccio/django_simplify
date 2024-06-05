# django_simplify Docker version
Script to create a basic Django site docker image 

Push this image on your dockerhub account

Launch a django site with daphne listening on port 80, with a volume mounted for /var/www/django with the code and the venv to simple editing out of container

# Create local docker


# Create your own docker repository
## Requirements
- dockerhub account
- precreated repository on dockerhub named django_simplify

## Using
- cd /tmp
- git clone https://github.com/lucapiccio/django_simplify.git
- chmod +x django_simplify/docker/make-docker.sh
- cd django_simplify/docker
- sudo ./make-docker.sh
