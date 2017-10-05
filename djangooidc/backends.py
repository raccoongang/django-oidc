# coding: utf-8

import re

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.validators import ValidationError
from django.db.models import Q
from student.forms import AccountCreationForm

from .models import Keycloak as KeycloakModel


class OpenIdConnectBackend(ModelBackend):

    def authenticate(self, request=None, **kwargs):
        user = None
        if not kwargs or 'sub' not in kwargs.keys():
            return user

        try:
            user = get_user_by_id(kwargs)
        except ValidationError:
            return None

        return user


def get_user_by_id(id_token):
    UserModel = get_user_model()
    uid = id_token['sub']
    username = clean_username(id_token['preferred_username'])

    from third_party_auth.pipeline import make_random_password

    openid_data = {
        'username': username,
        'firstname': '',
        'lastname': '',
        'password': make_random_password()
    }
    if 'first_name' in id_token.keys():
        openid_data['firstname'] = id_token['first_name']
    if 'given_name' in id_token.keys():
        openid_data['firstname'] = id_token['given_name']
    if 'christian_name' in id_token.keys():
        openid_data['firstname'] = id_token['christian_name']
    if 'family_name' in id_token.keys():
        openid_data['lastname'] = id_token['family_name']
    if 'last_name' in id_token.keys():
        openid_data['lastname'] = id_token['last_name']
    if 'email' in id_token.keys():
        openid_data['email'] = id_token['email']

    openid_data['name'] = ' '.join([openid_data['firstname'],
                                    openid_data['lastname']]).strip() or username

    try:
        kc_user = KeycloakModel.objects.get(uid=uid)
        user = kc_user.user
    except KeycloakModel.DoesNotExist:  # user doesn't exist with a keycloak UID
        user = UserModel.objects.filter(Q(username=username) | Q(email=openid_data.get('email'))).first()

        if user is None:
            form = AccountCreationForm(
                data=openid_data,
                extra_fields={},
                extended_profile_fields={},
                enforce_username_neq_password=False,
                enforce_password_policy=False,
                tos_required=False,
            )

            from student.views import _do_create_account

            (user, profile, registration) = _do_create_account(form)
            user.first_name = openid_data['firstname']
            user.last_name = openid_data['lastname']
            user.is_active = True
            user.set_unusable_password()
            user.save()

        KeycloakModel.objects.create(user=user, uid=uid)

    return user


def clean_username(username):
    """
    Performs any cleaning on the "username" prior to using it to get or
    create the user object.  Returns the cleaned username.
    """
    return re.sub('[\W]', '_', username)
