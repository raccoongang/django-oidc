Open EDX OpenID Connect (OIDC) authentication provider
======================================================

This module makes it easy to integrate OpenID Connect as an authentication source in a Open EDX project.

Behind the scenes, it uses Roland Hedberg's great pyoidc library.

Install and configure
---------------------

Install djangooidc::

    pip install git+https://github.com/raccoongang/django-oidc.git
    

Add in ``/edx/app/edxapp/lms.env.json``::

    "ADDL_INSTALLED_APPS" : [
        "djangooidc"
    ],
    
    "FEATURES" : {
        ...
        "ENABLE_COMBINED_LOGIN_REGISTRATION": true,
        "ENABLE_THIRD_PARTY_AUTH": true,
    }
    "THIRD_PARTY_AUTH_BACKENDS": ["djangooidc.backends.OpenIdConnectBackend"],
    
    "OIDC_SRV_DISCOVERY_URL": "https://localhost::8080/auth/realms/name_realm",
    "OIDC_CLIENT_ID": "client_id",
    "OIDC_CLIENT_SECRET": "client_secret",

Add in  ``lms/envs/aws.py``::

    LOGIN_URL = "/openid/openid/KeyCloak"
    LOGOUT_URL = "/openid/logout"
    
    OIDC_PROVIDERS = {
       'KeyCloak': {
           'srv_discovery_url': ENV_TOKENS.get('OIDC_SRV_DISCOVERY_URL'),
           'behaviour': {
               'response_type': 'code',
               'scope': ['openid', 'profile', 'email'],
           },
           'client_registration': {
               'client_id': ENV_TOKENS.get('OIDC_CLIENT_ID'),
               'client_secret': ENV_TOKENS.get('OIDC_CLIENT_SECRET'),
               'redirect_uris': [ '{}/openid/callback/login/'.format(LMS_ROOT_URL)],
               'post_logout_redirect_uris': ['{}/openid/callback/logout/'.format(LMS_ROOT_URL)],
           },
       }
    }

Add in ``lms/urls.py``::

    url(r'openid/', include('djangooidc.urls')),

Run migration::

    /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms migrate --settings=aws
