# django_simplify
Script to install a basic Django site with main structure and configuration, api support, bootstrap frontend, ecc...

# What the script do:
- Install all apt packages necessaires
- Create python venv and install django inside /var/www/django
- Install with pip all dependecies
- Configure django app:
  - core : the main django project with settings
  - users : custom user template to add fields at standard users django table
  - frontend: views for frontend
  - api: views and serializer for API Rest Framework
  - cron: planified task
- Create a systemd service to launch django with daphne asgi
  - core/asgi.py : startup code
  - /etc/systemd/system/django.service : systemd service
- Install and configure reverse proxy Nginx to serve django in SSL and serve the staticfiles
- Configure supervisor instead systemd if you have it, but i reccomends systemd service
- Create script run_debug_foreground.sh to launch django in foreground with actived debug
- Create script build.sh to rebuild / collect static / migrate / relaunch service

# How is configured
- core/urls.py : the Django urls + router for api urls
- cron/tasks.py : planified task
- users/models.py : definition model for users
- users/views.py : definition views for login - logout
- users/admin.py : definition views for django admin for users
- api/serializers.py + api/views.py : definitions of api models (need to adapt the router in core/urls.py)
- frontend/models.py : the models (tables of db) definitions
- frontend/views.py : the views for frontend
- templates/base_generic.html : the main template
- templates/index.html : template homepage 
- templates/login.html : template form login
- templates/signup.html : template user registration
- templates/css/base.css : custom CSS
