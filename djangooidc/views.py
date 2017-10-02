# coding: utf-8

import logging

from importlib import import_module
from django.conf import settings
from django.contrib.auth import logout as auth_logout, authenticate, login
from django.contrib.auth.views import logout as auth_logout_view
from django.http import HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import redirect, render_to_response, resolve_url
from django.http import HttpResponseRedirect
from djangooidc.oidc import OIDCClients, OIDCError
from djangooidc.models import SessionKey
from oic.oic import OpenIDSchema
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers

try:
    from urllib.parse import parse_qs
    from urllib.parse import urlencode
except ImportError:
    from urlparse import parse_qs
    from urllib import urlencode

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore

logger = logging.getLogger(__name__)


def get_client():
    configuration_settings = configuration_helpers.get_value('OIDC_PROVIDERS', settings.OIDC_PROVIDERS)
    return OIDCClients(configuration_settings)


def openid(request, op_name):
    request.session["next"] = request.GET["next"] if "next" in request.GET.keys() else "/"
    client = get_client()[op_name]
    request.session["op"] = op_name

    try:
        return client.create_authn_request(request.session)
    except Exception as e:
        return render_to_response("djangooidc/error.html", {"error": e})


# Step 4: analyze the token returned by the OP
def authz_cb(request):
    client = get_client()[request.session["op"]]
    query = None

    try:
        query = parse_qs(request.META['QUERY_STRING'])
        userinfo = client.callback(query, request.session)
        request.session["userinfo"] = userinfo
        user = authenticate(request=request, **userinfo)
        if user:
            session_key_old = request.session.session_key
            login(request, user)
            SessionKey.objects.create(old=session_key_old, new=request.session.session_key)
            return redirect(request.session["next"])
        else:
            raise Exception('this login is not valid in this application')
    except OIDCError as e:
        logging.getLogger('djangooidc.views.authz_cb').exception('Problem logging user in')
        return render_to_response("djangooidc/error.html", {"error": e, "callback": query})


def logout(request, next_page=None):
    if not "op" in request.session.keys():
        return auth_logout_view(request, next_page='/')

    client = get_client()[request.session["op"]]

    # User is by default NOT redirected to the app - it stays on an OP page after logout.
    # Here we determine if a redirection to the app was asked for and is possible.
    if next_page is None and "next" in request.GET.keys():
        next_page = request.GET['next']
    if next_page is None and "next" in request.session.keys():
        next_page = request.session['next']
    extra_args = {}
    if "post_logout_redirect_uris" in client.registration_response.keys() and len(
            client.registration_response["post_logout_redirect_uris"]) > 0:
        if next_page is not None:
            # First attempt a direct redirection from OP to next_page
            next_page_url = resolve_url(next_page)
            urls = [url for url in client.registration_response["post_logout_redirect_uris"] if next_page_url in url]
            if len(urls) > 0:
                extra_args["post_logout_redirect_uri"] = urls[0]
            else:
                # It is not possible to directly redirect from the OP to the page that was asked for.
                # We will try to use the redirection point - if the redirection point URL is registered that is.
                next_page_url = resolve_url('openid_logout_cb')
                urls = [url for url in client.registration_response["post_logout_redirect_uris"] if
                        next_page_url in url]
                if len(urls) > 0:
                    extra_args["post_logout_redirect_uri"] = urls[0]
                else:
                    # Just take the first registered URL as a desperate attempt to come back to the application
                    extra_args["post_logout_redirect_uri"] = client.registration_response["post_logout_redirect_uris"][
                        0]
    else:
        # No post_logout_redirect_uris registered at the OP - no redirection to the application is possible anyway
        pass

    # Redirect client to the OP logout page
    try:
        # DP HACK: Needed to get logout to actually logout from the OIDC Provider
        # According to ODIC session spec (http://openid.net/specs/openid-connect-session-1_0.html#RPLogout)
        # the user should be directed to the OIDC provider to logout after being
        # logged out here.

        request_args = {
            'id_token_hint': request.session['access_token'],
            'state': request.session['state'],
        }
        request_args.update(extra_args) # should include the post_logout_redirect_uri

        # id_token iss is the token issuer, the url of the issuing server
        # the full url works for the BOSS OIDC Provider, not tested on any other provider
        url = request.session['id_token']['iss'] + "/protocol/openid-connect/logout"
        url += "?" + urlencode(request_args)
        return HttpResponseRedirect(url)

        # Looks like they are implementing back channel logout, without checking for
        # support?
        # http://openid.net/specs/openid-connect-backchannel-1_0.html#Backchannel
        """
        request_args = None
        if 'id_token' in request.session.keys():
            request_args = {'id_token': IdToken(**request.session['id_token'])}
        res = client.do_end_session_request(state=request.session["state"],
                                            extra_args=extra_args, request_args=request_args)
        content_type = res.headers.get("content-type", "text/html") # In case the logout response doesn't set content-type (Seen with Keycloak)
        resp = HttpResponse(content_type=content_type, status=res.status_code, content=res._content)
        for key, val in res.headers.items():
            resp[key] = val
        return resp
        """
    finally:
        # Always remove Django session stuff - even if not logged out from OP. Don't wait for the callback as it may never come.
        auth_logout(request)
        if next_page:
            request.session['next'] = next_page


def logout_cb(request):
    return redirect("/")


@csrf_exempt
def k_logout(request):
    client = get_client()['KeyCloak']
    _schema = OpenIDSchema
    res = _schema().from_jwt(request.body,
                             keyjar=client.keyjar,
                             sender=client.provider_info["issuer"])
    logger.info('response KeyCloak - {}'.format(res.items()))

    if res.get('action', '') != 'LOGOUT' \
        and res.get('resource', '') != settings.ENV_TOKENS.get('OIDC_CLIENT_ID'):
        return HttpResponseBadRequest()

    try:
        session_key_old = res['adapterSessionIds'][0]
    except (KeyError, IndexError) as e:
        logger.info('k_logout except - {}'.format(e))
        pass
    else:
        session_key = SessionKey.objects.filter(old=session_key_old).first()
        if session_key:
            session = SessionStore(session_key=session_key.new)
            session.flush()
            session_key.delete()

    return redirect('/')
