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
        "OIDC_SRV_DISCOVERY_URL": "https://localhost:8080/auth/realms/name_realm",
        "OIDC_CLIENT_ID": "client_id",
        "OIDC_CLIENT_SECRET": "client_secret",
    }
    "THIRD_PARTY_AUTH_BACKENDS": ["djangooidc.backends.OpenIdConnectBackend"],

Add in  ``lms/envs/aws.py``::

    LOGIN_URL = "/openid/openid/KeyCloak"
    LOGOUT_URL = "/openid/logout"
    scheme = 'https' if HTTPS == 'on' else 'http'
    
    OIDC_PROVIDERS = {
       'KeyCloak': {
           'srv_discovery_url': FEATURES.get('OIDC_SRV_DISCOVERY_URL'),
           'behaviour': {
               'response_type': 'code',
               'scope': ['openid', 'profile', 'email'],
           },
           'client_registration': {
               'client_id': FEATURES.get('OIDC_CLIENT_ID'),
               'client_secret': FEATURES.get('OIDC_CLIENT_SECRET'),
               "redirect_uri": "%s://{}/openid/callback/login/" % scheme,
               'post_logout_redirect_uris': ['{}/openid/callback/logout/'.format(LMS_ROOT_URL)],
           },
       }
    }

Add in ``lms/urls.py``::

    url(r'openid/', include('djangooidc.urls')),

Run migration::

    /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms migrate --settings=aws
    
    
To use SLO  in edx, it is required to type ``"Admin URL" -> http://<localhost>/openid/``  in  keycloak  clients configurations

While microsites settings add to Site configurations the following strings::

   "OIDC_PROVIDERS":{
    "KeyCloak":{
        "srv_discovery_url":"http://localhost/auth/realms/name_realm",
        "behaviour":{
            "response_type":"code",
            "scope":["openid", "profile",  "email" ]
        },
        "client_registration":{
            "client_id":"client_id",
            "client_secret":"client_secret",
            "redirect_uri":"http://{}/openid/callback/login/",
            "post_logout_redirect_uris":["http://site1.localhost/openid/callback/logout/"]
      }
    }
  }

Example

    .. image:: img/microsites_settings.png
