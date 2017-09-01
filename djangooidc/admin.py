from django.contrib import admin

from .models import Keycloak


class KeycloakAdmin(admin.ModelAdmin):
    list_display = ('user', 'uid')


admin.site.register(Keycloak, KeycloakAdmin)
