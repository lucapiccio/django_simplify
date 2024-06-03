#!/bin/bash
#
# Copyright © 2024 Luca Piccinini <swipon83@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# DESCRIPTION:
# Script for installing Django in Venv on Debian System launched as systemd service with daphne asgi async python webserver
# Reverse proxy needed : nginx for serve static files
#
if [ ! -d "/var/www" ]; then
    mkdir -p /var/www
fi
if [ -d "/var/www/django" ]; then
    if [ -d "/var/www/django.old" ]; then
        rm -rf /var/www/django.old
    fi
    mv /var/www/django /var/www/django.old
fi
cd /var/www
## Install apt packages
apt-get install python3 python3-pip python3-venv python3-dev default-libmysqlclient-dev build-essential pkg-config
## Configure python virtual environnement
python3 -m venv django
cd django
source bin/activate
## install python requirements
if [ -f requirements.txt ]; then
    #git clone "yourRepo"
    pip install -r requirements.txt
else
    ## install python modules in venv
    pip install wheel
    pip install django
    pip install djangorestframework
    pip install gunicorn
    pip install daphne
    pip install h2
    pip install pymysql
    pip install mysqlclient
    pip install django-crontab
    pip install django-bootstrap-v5
    pip install fontawesomefree
    pip install django-bootstrap-modal-forms
    pip install django-redis
    pip install django-import-export
    pip install django-admin-interface
    pip install django-zxcvbn-password
    pip install django-tinymce
    ## Create Django project
    django-admin startproject core .
    ## Create app for custom user fields
    django-admin startapp users
    ## Create app for frontend views
    django-admin startapp frontend
    ## Create app for api routing
    django-admin startapp api
    ## Create app for crontab
    django-admin startapp cron
    mkdir templates
    mkdir templates/css
    mkdir templates/js
    mkdir templates/img
    mkdir templates/py
    mkdir templates/rest_framework
    touch templates/css/base.css
    touch templates/img/favicon.ico

    ## Create customuser model
cat <<EOF > users/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username.strip(), email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(username, email, password, **extra_fields)

class CustomUser(AbstractUser):
    # You can add fields that you want in your form not included in the Abstract User here
    # e.g Gender = model.CharField(max_length=10)
    USER_TYPE_CHOICES = (
        ('student', 'Student'),
        ('facilitator', 'Facilitator'),
        ('teamlead', 'Teamlead'),
    )
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES)

    username = models.CharField(
        max_length=150,
        unique=True,
        help_text='Required. 150 characters or fewer. Letters, digits, and spaces only.',
        validators=[],
        error_messages={
            'unique': "A user with that username already exists.",
        },
    )

    def is_facilitator(self):
        return self.user_type == 'facilitator'

    def is_student(self):
        return self.user_type == 'student'

    def is_teamlead(self):
        return self.user_type == 'teamlead'

    objects = CustomUserManager()
EOF
    ## Create django admin view for customuser
cat <<EOF > users/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    # Customize how the CustomUser model is displayed in the admin interface
    list_display = ('username', 'email', 'user_type', 'is_staff', 'date_joined')
    list_filter = ('user_type', 'is_staff')
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'email', 'user_type')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'user_type'),
        }),
    )

admin.site.register(CustomUser, CustomUserAdmin)
EOF
    ## Create the login-logout forms
cat <<EOF > users/forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import password_validation
from bootstrap_modal_forms.mixins import PopRequestMixin, CreateUpdateAjaxMixin
from bootstrap_modal_forms.forms import BSModalModelForm
from .models import CustomUser

class SignupForm(UserCreationForm):
    email = forms.EmailField(required=False, widget=forms.EmailInput(attrs={'class': 'form-control'}))
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'id': 'password-input'}),
        help_text=password_validation.password_validators_help_text_html(),
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )

    # Add an additional field for password strength
    password_strength = forms.CharField(
        widget=forms.HiddenInput(),
        required=False,
    )

    class Meta:
        model = CustomUser
        #fields = "__all__"
        fields = ['email','username','password1','password2','password_strength']

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

class UserModalForm(BSModalModelForm):
    class Meta:
        model = CustomUser
        fields = "__all__"
        #exclude = ['active','enabled','pid']
EOF
    ## Create view for login - logout
cat <<EOF > users/views.py
from django.shortcuts import render,redirect
from django.contrib.auth import authenticate, login, logout
from .forms import SignupForm, LoginForm
from django.contrib import messages

# signup page
def user_signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            username = form.cleaned_data['username']
            password1 = form.cleaned_data['password1']
            password2 = form.cleaned_data['password2']

            if password1 == password2:
                user.set_password(password1)
                user.save()
                messages.success(request, f'Your Account has been created {username} ! Proceed to log in')
                return redirect('login')
            else:
                form.add_error('password2', 'Passwords entered do not match')
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})

# login page
def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                return redirect('index')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

# logout page
def user_logout(request):
    logout(request)
    return redirect('login')
EOF
    ## Create frontend view for website
cat <<EOF > frontend/views.py
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.http import Http404,HttpResponse
from django.core.files import File
from bootstrap_modal_forms.generic import BSModalCreateView,BSModalUpdateView,BSModalDeleteView,BSModalReadView,BSModalFormView,BSModalLoginView
from django.views.decorators.http import require_http_methods
from .models import *
from users.models import *
from users.forms import *

# homepage
@login_required
def index(request):
    try:
        users_list = CustomUser.objects.order_by("username")
        context = {
            'users': users_list,
        }
    except :
        raise Http404("Object searched does not exist")
    return render(request,'index.html', context=context)

class UserCreateView(BSModalCreateView):
    template_name = 'form_create.html'
    form_class = UserModalForm
    success_message = 'Success!'
    success_url = reverse_lazy('index')

class UserUpdateView(BSModalUpdateView):
    template_name = 'form_edit.html'
    form_class = UserModalForm
    success_message = 'Success!'
    success_url = reverse_lazy('index')

class UserDeleteView(BSModalDeleteView):
    model = CustomUser
    template_name = 'form_delete.html'
    success_message = 'Success!'
    success_url = reverse_lazy('index')
EOF
    ## Configure API Serializers
cat <<EOF > api/serializers.py
from django.contrib.auth.models import Group, User
from rest_framework import serializers
from users.models import CustomUser

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['url', 'username', 'email', 'groups']

class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ['url', 'name']
EOF
    ## Configure API view
cat <<EOF > api/views.py
from django.shortcuts import render,redirect
from django.contrib.auth.models import Group, User
from rest_framework import permissions, viewsets
from rest_framework.views import APIView
from rest_framework.settings import api_settings
from users.models import CustomUser
from api.serializers import *

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = CustomUser.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ['get', 'head']


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all().order_by('name')
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ['get', 'head']

EOF
    ## Create base template
cat <<EOF > templates/base_generic.html
{% load static %}
{% load i18n %}
{% load bootstrap5 %}
<!DOCTYPE html>
<html lang="en">
  <head>
  {% block head %}
    {% block title %}
      <title>Django</title>
    {% endblock %}
    {% block meta %}
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <meta name="robots" content="NONE,NOARCHIVE" />
        <link rel="icon" href="{% static 'img/favicon.ico' %}">
        <!-- CSS -->
        {% bootstrap_css %}
        <link rel="stylesheet" href="{% static 'fontawesomefree/css/all.min.css' %}?{% now "U" %}" type="text/css">
        <link rel="stylesheet" href="{% static 'css/base.css' %}?{% now "U" %}" type="text/css">
        <!-- JS -->
        {% bootstrap_javascript %}
        <script src="{% static 'fontawesomefree/js/all.min.js' %}?{% now "U" %}"></script>
        <script src="{% static "tinymce/tinymce.min.js" %}?{% now "U" %}"></script>
        <script src="{% static "js/custom_modal.js" %}?{% now "U" %}"></script>
    {% endblock %}
  {% endblock %}
  </head>
  <body>
    <div class="wrapper">
        {% block navbar %}
        <div class="navbar navbar-expand-md navbar-dark bg-dark fixed-top" role="navigation" aria-label="navbar">
            <ul class="nav navbar-nav pull-right">
                <li><a class='nav-link' href="{% url 'index' %}">Home</a></li>
                {% block userlinks %}
                    {% if user.is_authenticated %}
                        <li><a class='nav-link' href="/api">API browser</a></li>
                        <li><a class='nav-link' href="{% url 'logout' %}">Logout</a></li>
                        {% if user.is_staff %}
                            <li><a class='nav-link' href="{% url 'admin:index' %}">Django Admin</a></li>
                        {% endif %}
                    {% else %}
                        <li><a class='nav-link' href="{% url 'login' %}">Login</a></li>
                    {% endif %}
                {% endblock %}
            </ul>
        </div><!-- /.navbar -->
        {% endblock %}
        <div class="container text-center">
            <div class="modal fade" id="create-modal" tabindex="-1" role="dialog" aria-hidden="true">
              <div class="modal-dialog mt-5">
                <div class="modal-content">
                </div>
              </div>
            </div>
            
            <div class="modal fade" tabindex="-1" role="dialog" id="modal">
              <div class="modal-dialog mt-5" role="document">
                <div class="modal-content"></div>
              </div>
            </div>
            <div id="row content" role="main" >
            {% block content %}{% endblock %}
            </div><!-- /.content -->
        </div><!-- /.container -->
    </div><!-- /.wrapper -->
    {% block script %}
    {% endblock %}
  </body>
</html>
EOF
    ## Create template index
cat <<EOF > templates/index.html
{% extends "base_generic.html" %}
{% load i18n %}
{% load static %}
{% block content %}
{% if user.is_authenticated %}
    <h3>Home</h3>
    <div class="card">
        <div class="card-header">
            <h5>Datas</h5><br />
            <button data-toggle="modal" class='edit_printer bs-modal btn btn-primary btn-sm hint--top-left' aria-label="Edit" type="button"><i class="fa-solid fa-pencil"></i></button>
            <button aria-label="script d'installation de l'imprimante" role="button" class="btn btn-secondary hide-btn-content hint--top btn-sm"> <i class="fa fa-solid fa-cloud-arrow-down"> </i> </button></a>
            <button aria-label="Delete" onclick="return confirm('Delete ?');" type="button" class="btn btn-danger btn-sm hint--top-left" data-target="#delete-button-modal-undefined-clermont"> <i class="fa-solid fa-trash-can"></i></button>
        </div>
    </div>
{% endif %}
{% endblock %}
EOF
    ## Create template login
cat <<EOF > templates/login.html
{% extends "base_generic.html" %}
{% load i18n %}
{% load static %}

{% block content %}
  <h1>Login</h1>
  <form method="POST">
    {% csrf_token %}
    {{ form.as_p }}
    <button type="submit">Login</button>
    <a href="{% url 'signup' %}">Dont have Account?</a>
  </form>
{% endblock %}
EOF
    ## Create template user registration
cat <<EOF > templates/signup.html
{% extends "base_generic.html" %}
{% load i18n %}
{% load static %}

{% block content %}
  <h1>Signup</h1>
  <form method="POST">
    {% csrf_token %}
    <div data-mdb-input-init class="form-outline mb-4">
    {% for field in form %}
        <div class="row mb-4">
            <div class="col d-flex justify-content-center">
            {{ field.label_tag }}
            </div>
            <div class="col">
            {{ field }}
            </div>
        </div>
        <div class="row mb-4">
        {% for error in field.errors %}
            {{ error }}
        {% endfor %}
        </div>
    <button type="submit" class="btn btn-primary" style="margin-top: 8px;">Signup</button>
    <a href="{% url 'login' %}">Already have account?</a>
  </form>
  <script type="text/javascript" src="{% static 'zxcvbn_password/js/zxcvbn.js' %}?{% now "U" %}"></script>
  <script>
  document.addEventListener('DOMContentLoaded', function () {
    const passwordInput = document.getElementById('password-input');
    const passwordStrengthField = document.getElementById('password-strength');

    passwordInput.addEventListener('input', function () {
        const password = passwordInput.value;
        const result = zxcvbn(password);

        // Update password strength feedback
        passwordStrengthField.innerHTML = ''; // Clear previous feedback

        if (result.score === 0) {
            passwordStrengthField.innerHTML = '<span style="color: red;">Very Weak</span>';
        } else if (result.score === 1) {
            passwordStrengthField.innerHTML = '<span style="color: orange;">Weak</span>';
        } else if (result.score === 2) {
            passwordStrengthField.innerHTML = '<span style="color: yellow;">Medium</span>';
        } else if (result.score === 3) {
            passwordStrengthField.innerHTML = '<span style="color: green;">Strong</span>';
        } else if (result.score === 4) {
            passwordStrengthField.innerHTML = '<span style="color: darkgreen;">Very Strong</span>';
        }
    });
  });
  </script>
{% endblock %}
EOF

## Create personal CSS
cat <<EOF > templates/css/base.css
.container {
    padding-top: 70px;
}
EOF

    ## Create template api Rest
cat <<EOF > templates/rest_framework/api.html
{% extends "rest_framework/base.html" %}
{% block title %} API {% endblock %}
{% block branding %}
    <span>
        <a class='navbar-brand' rel="nofollow" href="{% url 'index' %}">Home</a>
{% endblock %}
{% block bootstrap_navbar_variant %}
{% endblock %}
EOF

## Modal Create
cat <<EOF > templates/form_create.html
<form method="post" action="">
  {% csrf_token %}

 <div class="modal-header">
    <h5 class="modal-title">Create new</h5>
    <button type="button" class="close" data-bs-dismiss="modal" data-dismiss="modal" aria-label="Close">
      <span aria-hidden="true">&times;</span>
    </button>
  </div>

  <div class="modal-body">
    {% for field in form %}
      <div class="form-group{% if field.errors %} invalid{% endif %}">
        <label for="{{ field.id_for_label }}">{{ field.label }}</label>
        {{ field }}
        <br />
        {% for error in field.errors %}
          <p class="help-block">{{ error }}</p>
        {% endfor %}
      </div>
    {% endfor %}
  </div>

  <div class="modal-footer">
    <button type="button" class="btn btn-default" data-bs-dismiss="modal" data-dismiss="modal">Close</button>
    <button type="submit" class="btn btn-primary">Create</button>
  </div>

</form>
EOF

## Modal EDIT
cat <<EOF > templates/form_edit.html
<form method="post" action="">
  {% csrf_token %}

 <div class="modal-header">
    <h5 class="modal-title">Modify</h5>
    <button type="button" class="close" data-bs-dismiss="modal" data-dismiss="modal" aria-label="Close">
      <span aria-hidden="true">&times;</span>
    </button>
  </div>

  <div class="modal-body">
    <div class="{% if form.non_field_errors %}invalid{% endif %} mb-2">
      {% for error in form.non_field_errors %}
        {{ error }}
      {% endfor %}
    </div>
    {% for field in form %}
      <div class="form-group{% if field.errors %} invalid{% endif %}">
        <label for="{{ field.id_for_label }}">{{ field.label }}</label>
        {% render_field field class="form-control" placeholder=field.label %}
        <div class="{% if field.errors %} invalid{% endif %}">
          {% for error in field.errors %}
            <p class="help-block">{{ error }}</p>
          {% endfor %}
        </div>

        <br />
        {% for error in field.errors %}
          <p class="help-block">{{ error }}</p>
        {% endfor %}
      </div>
    {% endfor %}
  </div>

  <div class="modal-footer">
    <button type="button" class="btn btn-default" data-bs-dismiss="modal" data-dismiss="modal">Close</button>
    <button type="submit" class="btn btn-primary">Update</button>
  </div>
</form>
EOF

## Modal Delete
cat <<EOF > templates/form_delete.html
{% load widget_tweaks %}

<form method="post" action="">
  {% csrf_token %}

  <div class="modal-header">
    <h3 class="modal-title">Delete</h3>
    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
      <span aria-hidden="true">&times;</span>
    </button>
  </div>
  <div class="modal-body">
    <p class="delete-text">Are you sure you want to delete?</p>
  </div>
  <div class="modal-footer">
    <button type="submit" id="delete-btn" class="btn btn-danger">Delete</button>
  </div>
</form>
EOF

## Create custom javascript to edit form
cat <<EOF > templates/js/custom_modal.js
// Update book asynchronous button
// message
var asyncSuccessMessageUpdate = [
    "<div ",
    "style='position:fixed;top:0;z-index:10000;width:100%;border-radius:0;' ",
    "class='alert alert-icon alert-success alert-dismissible fade show mb-0' role='alert'>",
    "Success: Updated.",
    "<button type='button' class='close' data-dismiss='alert' aria-label='Close'>",
    "<span aria-hidden='true'>&times;</span>",
    "</button>",
    "</div>",
    "<script>",
    "\$('.alert').fadeTo(2000, 500).slideUp(500, function () {\$('.alert').slideUp(500).remove();});",
    "<\/script>"
].join("");

// modal form
function updateBookModalForm() {
    \$(".update-book").each(function () {
        \$(this).modalForm({
            formURL: \$(this).data("form-url"),
            asyncUpdate: true,
            asyncSettings: {
                closeOnSubmit: false,
                successMessage: asyncSuccessMessageUpdate,
                dataUrl: "books/",
                dataElementId: "#books-table",
                dataKey: "table",
                addModalFormFunction: reinstantiateModalForms
            }
        });
    });
}
//updateBookModalForm();

// Delete book buttons - formURL is retrieved from the data of the element
function deleteBookModalForm() {
    \$(".delete-book").each(function () {
        \$(this).modalForm({formURL: \$(this).data("form-url"), isDeleteForm: true});
    });
}
//deleteBookModalForm();
EOF

cat <<EOF > templates/400.html
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Site Maintenance</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px; margin: 0 auto; }
  a { color: #dc8100; text-decoration: none; }
  a:hover { color: #333; text-decoration: none; }
</style>
</head>
<body>
<article>
    <h1>We&rsquo;ll be back soon!</h1>
    <br>
    <div>
    <h3>400 Bad Request</h3>
    <h4>The server cannot or will not process the request due to an apparent client error</h4>
    </div>
    <div>
        <p>Sorry for the inconvenience but we&rsquo;re performing some maintenance at the moment. If you need to you can always <a href="mailto:webmaster@localhost">contact us</a>, otherwise we&rsquo;ll be back online shortly!</p>
    </div>
</article>
</body>
</html>
EOF

cat <<EOF > templates/403.html
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Site Maintenance</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px; margin: 0 auto; }
  a { color: #dc8100; text-decoration: none; }
  a:hover { color: #333; text-decoration: none; }
</style>
</head>
<body>
<article>
    <h1>We&rsquo;ll be back soon!</h1>
    <br>
    <div>
    <h3>403 Forbidden</h3>
    <h4>The request contained valid data and was understood by the server, but the server is refusing action</h4>
    </div>
    <div>
        <p>Sorry for the inconvenience but we&rsquo;re performing some maintenance at the moment. If you need to you can always <a href="mailto:webmaster@localhost">contact us</a>, otherwise we&rsquo;ll be back online shortly!</p>
    </div>
</article>
</body>
</html>
EOF

cat <<EOF > templates/404.html
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Site Maintenance</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px; margin: 0 auto; }
  a { color: #dc8100; text-decoration: none; }
  a:hover { color: #333; text-decoration: none; }
</style>
</head>
<body>
<article>
    <h1>We&rsquo;ll be back soon!</h1>
    <br>
    <div>
    <h3>404 Not Found</h3>
    <h4>The requested resource could not be found but may be available in the future</h4>
    </div>
    <div>
        <p>Sorry for the inconvenience but we&rsquo;re performing some maintenance at the moment. If you need to you can always <a href="mailto:webmaster@localhost">contact us</a>, otherwise we&rsquo;ll be back online shortly!</p>
    </div>
</article>
</body>
</html>
EOF

cat <<EOF > templates/500.html
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Site Maintenance</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px; margin: 0 auto; }
  a { color: #dc8100; text-decoration: none; }
  a:hover { color: #333; text-decoration: none; }
</style>
</head>
<body>
<article>
    <h1>We&rsquo;ll be back soon!</h1>
    <br>
    <div>
    <h3>500 Internal Server Error</h3>
    <h4>An internal server error occured.</h4>
    </div>
    <div>
        <p>Sorry for the inconvenience but we&rsquo;re performing some maintenance at the moment. If you need to you can always <a href="mailto:webmaster@localhost">contact us</a>, otherwise we&rsquo;ll be back online shortly!</p>
    </div>
</article>
</body>
</html>
EOF

    ## Configure Additional Settings
    /usr/bin/sed -i "s/from pathlib import Path/import os\nfrom pathlib import Path/" core/settings.py
    /usr/bin/sed -i "s/ALLOWED_HOSTS =.*/ALLOWED_HOSTS = ['*']/" core/settings.py
    /usr/bin/sed -i "s/DEBUG =.*/DEBUG = False/" core/settings.py
    /usr/bin/sed -i "s/INSTALLED_APPS = \[/INSTALLED_APPS = \[\n    'daphne',/" core/settings.py
    /usr/bin/sed -i "s/'django.contrib.staticfiles',/'django.contrib.staticfiles',\n    'rest_framework',\n    'django_crontab',\n    'bootstrap_modal_forms',\n    'bootstrap5',\n    'fontawesomefree',\n    'zxcvbn_password',\n    'import_export',\n    'tinymce',\n    'users',\n    'frontend',\n    'api',\n    'cron',/" core/settings.py
    /usr/bin/sed -i "s/'django.contrib.admin',/'admin_interface',\n    'colorfield',\n    'django.contrib.admin',/" core/settings.py

cat <<EOF >> core/settings.py
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATICFILES_DIRS = [
    ('css',os.path.join(BASE_DIR, 'templates', 'css')),
    ('js',os.path.join(BASE_DIR, 'templates', 'js')),
    ('img',os.path.join(BASE_DIR, 'templates', 'img')),
    ('py',os.path.join(BASE_DIR, 'templates', 'py')),
]
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
MEDIA_URL = 'media/'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

CRONJOBS = [
    ('* * * * *', 'cron.tasks.loop'),
    ('*/5 * * * *', 'cron.tasks.cyclicfast'),
    ('*/15 * * * *', 'cron.tasks.cyclic'),
    ('0 * * * *', 'cron.tasks.hourly'),
    ('0 8 * * *', 'cron.tasks.daily'),
    ('0 * * * 7', 'cron.tasks.weekly'),
    ('0 8 1 * *', 'cron.tasks.monthly'),
    ('0 8 1 1 *', 'cron.tasks.yearly'),
]

REST_FRAMEWORK = {
    ## Render for api export/communication
    'DEFAULT_RENDERER_CLASSES': (
        ## Web
        'rest_framework.renderers.BrowsableAPIRenderer',
        ## Json
        'rest_framework.renderers.JSONRenderer',
    ),
    ## API permissions
    'DEFAULT_AUTHENTICATION_CLASSES': (
        ## Use site auth for use the same users
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        ## Only authenticated
        'rest_framework.permissions.IsAuthenticated',
    ),
}

AUTH_USER_MODEL = 'users.CustomUser'
LOGIN_REDIRECT_URL = '/'
LOGIN_URL = '/login/'
LOGOUT_REDIRECT_URL = '/'
PASSWORD_RESET_TIMEOUT = '259200'

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'zxcvbn_password.ZXCVBNValidator',
        'OPTIONS': {
            'min_score': 3,
            'user_attributes': ('username', 'email', 'first_name', 'last_name')
        }
    }
]

SECURE_SSL_REDIRECT = False
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
USE_X_FORWARDED_PORT = True
USE_X_FORWARDED_HOST = True
X_FRAME_OPTIONS = 'SAMEORIGIN'
SILENCED_SYSTEM_CHECKS = ["security.W019"]

ASGI_APPLICATION = 'core.asgi.application'
EOF

    ## Configure ASGI Async webserver startup
cat <<EOF > core/asgi.py
import os
import django
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()
from django.conf import settings
from cron import tasks as tasks
from django.apps import AppConfig
application = get_asgi_application()
## Startup launch
tasks.boot()
EOF

#### Using redis as cache server
if [ ! -d /etc/redis ] ; then
    apt install redis-server
fi

cat <<EOF >> core/settings.py
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "SOCKET_CONNECT_TIMEOUT": 5, 
            "SOCKET_TIMEOUT": 5,
        },
        "KEY_PREFIX": "django"
    }
}
DJANGO_REDIS_IGNORE_EXCEPTIONS = True
DJANGO_REDIS_LOG_IGNORED_EXCEPTIONS = True
EOF

    ## Creating Cron jobs
cat <<EOF > cron/tasks.py
from django.core.mail import send_mail

def boot():
    print("Launch Startup Application")

## Every minute
def loop():
    print('Crontab: loop')

## Every 5 minutes
def cyclicfast():
    print('Crontab: cyclicfast')

## Every 15 minutes
def cyclic():
    print('Crontab: cyclic')

def hourly():
    print('Crontab: hourly')
    checkTunnelsStatus()

def daily():
    print('Crontab: daily')

def weekly():
    print('Crontab: weekly')

def monthly():
    print('Crontab: monthly')

def yearly():
    print('Crontab: yearly')

EOF

    ## Create the urls for django
cat <<EOF > core/urls.py
import os
from django.contrib import admin
from django.urls import path,include
from django.conf.urls.i18n import i18n_patterns
from rest_framework import routers
from frontend import views as frontendviews
from api import views as apiviews
from users import views as usersviews
from cron import tasks as tasks

## Startup launch if launched in wsgi (gunicorn)
if os.environ.get('RUN_MAIN', None):
    print("##############BOOT#############")
    tasks.boot()

## Admin Site Personnalisation
admin.site.site_header = "Django Application"
admin.site.site_title = "Django Application"
admin.site.index_title = "Django Application Admin"

## Router for API
router = routers.DefaultRouter()
router.register(r'users', apiviews.UserViewSet)
router.register(r'groups', apiviews.GroupViewSet)

urlpatterns = [
    ## Django native Administration
    path('admin/', admin.site.urls, name='admin'),
    ## Homepage
    path('', frontendviews.index, name='index'),
    path('home/', frontendviews.index, name='home'),
    ## User Login / Signup / Logout
    path('login/', usersviews.user_login, name='login'),
    path('signup/', usersviews.user_signup, name='signup'),
    path('logout/', usersviews.user_logout, name='logout'),
    ## Api
    path('api/', include(router.urls)),
    ## Enabling authentification for api
    path('api-auth/', include('rest_framework.urls')),
    ## TinyMCE
    path('tinymce/', include('tinymce.urls')),
    ## Modal EDIT
    path('create/<int:pk>', frontendviews.UserCreateView.as_view(), name='create_user'),
    path('update/<int:pk>', frontendviews.UserUpdateView.as_view(), name='update_user'),
    path('delete/<int:pk>', frontendviews.UserDeleteView.as_view(), name='delete_user'),
]
EOF
    pip freeze > requirements.txt
fi

## If mysql create the database (django migrate will create tables)
DATABASE=$(grep ENGINE core/settings.py | grep -v \# |awk '{print $2}' | sed s/\'//g | sed s/\"//g | sed s/\,//g)
if [ $DATABASE == "django.db.backends.mysql" ] ; then
    echo "creating Mysql/Mariadb Database, Django doesn't create the db, only the tables"
    mysql -e "CREATE DATABASE IF NOT EXISTS django"
fi

## Collect all template and static files in static folder configured in settings
python3 manage.py collectstatic --clear --noinput

## Prepare the migrations for the DB
python3 manage.py makemigrations

## Write the modification to the DB
python3 manage.py migrate

## Create a default superuser admin admin
DJANGO_SUPERUSER_USERNAME=admin \
DJANGO_SUPERUSER_PASSWORD=admin \
DJANGO_SUPERUSER_EMAIL="admin@localhost" \
python3 manage.py createsuperuser --noinput

## Add templates for admin page
python3 manage.py loaddata admin_interface_theme_bootstrap.json
python3 manage.py loaddata admin_interface_theme_foundation.json
python3 manage.py loaddata admin_interface_theme_uswds.json

## Create user alias of www-data (UID 33) for editing and have bash shell to launch in debug mode
useradd --badname -d /var/www/django -M -g 33 -N -u 33 -o -s /bin/bash django

cat <<EOF > /var/www/django/.bashrc
case \$- in
    *i*) ;;
      *) return;;
esac
HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=1000
HISTFILESIZE=2000

PS1='${debian_chroot:+(\$debian_chroot)}[\d \t] \[\033[0;32m\]\u@\h:\[\033[0;37m\]\[\033[01;34m\][\w]\[\033[00m\]\\$\[\033[0m\] '

alias rm='rm -i'
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
source ~/bin/activate
EOF

## Set Rights to apache/nginx user
chown -R www-data:www-data /var/www/django

## Install django crontab on root crontab (app cron/tasks.py)
python3 manage.py crontab remove
python3 manage.py crontab add

#### Needed reverse proxy (to serve static files and optionally to configure websockets)
if [ ! -d "/etc/nginx" ]; then
    apt install nginx php-fpm
fi
cat <<EOF > /etc/nginx/sites-available/django_upstream
map \$http_upgrade \$connection_upgrade {
        default upgrade;
        ''      close;
}

upstream supervisor {
        server 127.0.0.1:8000;
}
EOF

cat <<EOF > /etc/nginx/sites-available/django_https
server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name _;
        #set_real_ip_from    127.0.0.1;
        real_ip_header      X-Forwarded-For;
        root /var/www/django;
        index index.php index.html index.htm;
        include /etc/nginx/snippets/snakeoil.conf;
        ssl_prefer_server_ciphers on;  # prefer a list of ciphers to prevent old and slow ciphers
        ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
        ssl_buffer_size 4k;
        ssl_session_cache   shared:SSL:50m;
        ssl_session_timeout 4h;

        #OCSP
        ssl_stapling off;
        ssl_stapling_verify off;
        add_header Strict-Transport-Security "max-age=15552000; includeSubdomains; preload";
        ignore_invalid_headers off;

        location ~ ^/(\.user.ini|\.htaccess|\.git|\.svn|\.project|LICENSE|README.md)
        {
                return 404;
        }
        location ^~ \.well-known{
                allow all;
                location ~ \.php$ {
                        include snippets/fastcgi-php.conf;
                        fastcgi_pass unix:/run/php/php-fpm.sock;
                }
        }

        location ^~ /static/
        {
                root /var/www/django/static;
                autoindex off;
                sendfile           on;
                tcp_nopush on;
                rewrite  ^/static/(.*) /\$1 break;
                location ~ \.php$ {
                        rewrite  ^/static/(.*) /\$1 break;
                        include snippets/fastcgi-php.conf;
                        fastcgi_pass unix:/run/php/php-fpm.sock;
                }
        }
        location /
        {
                proxy_pass http://supervisor;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_set_header REMOTE-HOST \$remote_addr;
                proxy_set_header X-Forwarded-Ssl on;
                proxy_set_header X-Forwarded-Proto \$scheme;
                proxy_set_header X-Forwarded-Host \$http_host;
                proxy_pass_header       Set-Cookie;
                proxy_redirect off;
                proxy_buffering off;
                proxy_socket_keepalive on;

                add_header Strict-Transport-Security "max-age=0;";

                #Set Nginx Cache
                proxy_no_cache 1;
                proxy_cache_bypass 1;
                add_header Cache-Control no-cache;
                expires -1;

                proxy_connect_timeout 86400s;
                proxy_send_timeout 86400s;
                proxy_read_timeout 86400s;
                proxy_ignore_client_abort on;

                ## CSRF
                proxy_set_header X-XSRF-TOKEN \$http_x_xsrf_token;
                proxy_set_header Token \$http_token;
                proxy_pass_header  Token;

                ## Is Websocket
                proxy_http_version 1.1;
                proxy_set_header Upgrade \$http_upgrade;
                proxy_set_header Connection \$connection_upgrade;
        }
}
EOF

cat <<EOF > /etc/nginx/sites-available/django_http
server {
        listen 80;
        listen [::]:80;
        server_name _;
        return 301 https://\$host\$request_uri;
}
EOF
rm -f /etc/nginx/sites-enabled/*
ln -s /etc/nginx/sites-available/django_* /etc/nginx/sites-enabled/
systemctl daemon-reload
service nginx restart

## Install the systemd service to autolaunch python asgi webserver
if [ -d "/etc/systemd" ]; then
cat <<EOF > /etc/systemd/system/django.service
[Unit]
Description=Unit for starting a basic Django app
Requires=network.target
After=network.target
After=syslog.target

[Service]
Type=simple
Restart=on-failure
WorkingDirectory=/var/www/django
ExecStart=/var/www/django/bin/daphne core.asgi:application --proxy-headers --port 8000 --bind 0.0.0.0 -v1
TimeoutStartSec=0
RestartSec=10
Restart=on-failure
User=www-data
KillSignal=SIGQUIT

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        service django restart
fi

## Prefer Systemd directly to reduce num of software installed
if [ -d "/etc/supervisor/conf.d" ]; then
cat <<EOF > /etc/supervisor/conf.d/django.conf
[program:django]
environment=PATH="/var/www/django/bin"
command=/var/www/django/bin/daphne core.asgi:application --proxy-headers --port 8000 --bind 0.0.0.0 -v1
##command=/var/www/django/bin/gunicorn --env DJANGO_SETTINGS_MODULE=core.settings --chdir /var/www/django --workers 3 --bind 0.0.0.0:8000 core.wsgi:application
process_name=asgi%(process_num)d
user=www-data
directory=/var/www/django
autostart=true
autorestart=true
stopwaitsecs=1
stopsignal=TERM
stopasgroup=true
killasgroup=true
stdout_logfile=/var/log/supervisor/django.log
EOF
       systemctl daemon-reload
       service supervisor restart
fi

## Prepare simplify the reloading of code
cat <<EOF > build.sh
#!/bin/bash
source bin/activate
/usr/bin/sed -i "s/DEBUG =.*/DEBUG = False/" core/settings.py
pip freeze > requirements.txt
python3 manage.py collectstatic --clear --noinput
python3 manage.py makemigrations
python3 manage.py migrate
chown -R www-data:www-data /var/www/django
#crontab -r
#python3 manage.py crontab remove
#python3 manage.py crontab add
#service supervisor restart
service django restart
service nginx restart
EOF
chmod +x build.sh
chown -R www-data:www-data build.sh

cat <<EOF > run_debug_foreground.sh
#!/bin/bash
service django stop
source bin/activate
/usr/bin/sed -i "s/DEBUG =.*/DEBUG = True/" core/settings.py
#python manage.py runcrons --force
#django-admin compilemessages
#python3 manage.py runserver --insecure 0.0.0.0:8000
/var/www/django/bin/daphne core.asgi:application --proxy-headers --port 8000 --bind 0.0.0.0 -v3
/usr/bin/sed -i "s/DEBUG =.*/DEBUG = False/" core/settings.py
EOF
chmod +x run_debug_foreground.sh
chown -R www-data:www-data run_debug_foreground.sh

cat <<EOF > .vimrc
"Active function arrow keys
set nocompatible

"Active syntax
if has('filetype')
        filetype off
endif
if has('syntax')
        syntax on
endif

"Active lines num
set number

"Set color more visibles
set background=dark

"filetype plugin indent on
set autoindent
set showmode
set showcmd

set history=1000
set hlsearch
set showmatch

" Python compatibility
set tabstop=4
set shiftwidth=4
set softtabstop=4
set expandtab

" Return to last line
au BufReadPost * if line("'\"") > 1 && line("'\"") <= line("$") | exe "normal! g'\"" | endif

"Active bar en bas avec details sur le fichier
if has('statusline')
        set laststatus=2
        set statusline+=%w%h%m%r
        set statusline+=\ [%{getcwd()}/%<%f]
"       set statusline+=\ [%{&ff}/%Y] " filetype
        set statusline+=%=%-14.(%l,%c%V%)\ %p%% " Right aligned file nav info
endif

"force numbers function of numpad
inoremap <Esc>Oq 1
inoremap <Esc>Or 2
inoremap <Esc>Os 3
inoremap <Esc>Ot 4
inoremap <Esc>Ou 5
inoremap <Esc>Ov 6
inoremap <Esc>Ow 7
inoremap <Esc>Ox 8
inoremap <Esc>Oy 9
inoremap <Esc>Op 0
inoremap <Esc>On .
inoremap <Esc>OQ /
inoremap <Esc>OR *
inoremap <Esc>Ol +
inoremap <Esc>OS -
inoremap <Esc>OM <Enter>
nnoremap <esc>^[ <esc>^[
EOF
chown -R www-data:www-data .vimrc
deactivate

echo "To login in django venv do:"
echo "cd /var/www/django && su django"

cd /var/www/django && su django
