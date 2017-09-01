from django.conf import settings
from django.db import models


class Keycloak(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    uid = models.CharField(max_length=255, primary_key=True)


class SessionKey(models.Model):
    old = models.CharField(max_length=40)
    new = models.CharField(max_length=40)
