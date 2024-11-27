import datetime
import logging

from jose import jwt
from panel.auth import OAuthLoginHandler
from panel.config import config
from panel.io.resources import (
    BASIC_LOGIN_TEMPLATE,
    CDN_DIST,
)
from tornado.web import HTTPError

from panel_auth_credfile.config import CFG
from panel_auth_credfile.credentials import CREDS_FILE, User, cmp_password


class CredfileLoginHandler(OAuthLoginHandler):
    _access_token_header = "Bearer {}"
    _login_template = BASIC_LOGIN_TEMPLATE
    _EXTRA_TOKEN_PARAMS = {"grant_type": "password"}
    _USER_KEY = "username"  # user identifier field in id_token
    # this class is mounted as a panel.auth plugin
    logger = logging.getLogger("panel.auth.credfile")

    async def get(self):
        try:
            errormessage = self.get_argument("error")
        except Exception:
            errormessage = ""

        next_url = self.get_argument("next", None)
        if next_url:
            self.set_cookie("next_url", next_url)
        html = self._login_template.render(errormessage=errormessage, PANEL_CDN=CDN_DIST)
        self.write(html)

    async def post(self):
        username = self.get_argument("username", "")
        password = self.get_argument("password", "")
        try:
            user, _, _, _ = await self._fetch_access_token(
                config.oauth_key,
                username=username,
                password=password,
            )
        except Exception as e:
            self.logger.warning(
                "Authentication failed for user: %s [%s]", username, self.request.remote_ip
            )
            raise e
        if not user:
            return
        self.logger.info(
            "Successfully authenticated user: %s [%s]", username, self.request.remote_ip
        )
        self.redirect("/")

    async def _fetch_access_token(
        self,
        client_id,
        redirect_uri=None,
        client_secret=None,
        code=None,
        refresh_token=None,
        username=None,
        password=None,
    ):
        """
        Fetches the access token.

        Arguments
        ---------
        client_id:
          The client ID
        redirect_uri:
          The redirect URI
        code:
          The response code from the server
        client_secret:
          The client secret
        refresh_token:
          A token used for refreshing the access_token
        username:
          A username
        password:
          A password
        """
        self.logger.debug("%s making access token request.", type(self).__name__)
        params = {**self._EXTRA_TOKEN_PARAMS}
        if refresh_token:
            refreshing = True
            params["refresh_token"] = refresh_token
            params["grant_type"] = "refresh_token"
        else:
            refreshing = False
        if username:
            params.update(username=username, password=password)

        body = token_endpoint(params)
        if "access_token" not in body:
            if refresh_token:
                self.logger.debug(
                    "%s token endpoint did not reissue an access token.", type(self).__name__
                )
                return None, None, None
            self._raise_error_plain(body, status=401, error="authentication failed")

        expires_in = body.get("expires_in")
        if expires_in:
            expires_in = int(expires_in)

        access_token, refresh_token = body["access_token"], body.get("refresh_token")
        if refreshing:
            # When refreshing the tokens we do not need to re-fetch the id_token or user info
            return None, access_token, refresh_token, expires_in
        id_token = body["id_token"]
        try:
            user = OAuthLoginHandler.set_auth_cookies(
                self, id_token, access_token, refresh_token, expires_in
            )
        except HTTPError:
            self.logger.debug("%s could not set the auth cookies.", type(self).__name__)
            self._raise_error_plain(body, status=500)
        self.logger.debug(
            "%s successfully obtained access_token and id_token.", type(self).__name__
        )
        return user, access_token, refresh_token, expires_in

    def _raise_error_plain(self, body=None, status=400, error=None, error_description=None):
        provider = self.__class__.__name__.replace("LoginHandler", "")
        if error:
            self.logger.error(
                "%s OAuth provider returned a %s error. The full response was: %s",
                provider,
                error,
                body,
            )
        else:
            self.logger.warning(
                "%s OAuth provider failed to fully authenticate returning the following response: %s.",
                provider,
                body,
            )
        raise HTTPError(
            status,
            error_description or str(body),
            reason=error or "Unknown error",
        )


class UserRequestFailed(Exception):
    pass


def get_user_data(params) -> User:
    user_data = CREDS_FILE().get(params["username"])
    if user_data is None:
        raise UserRequestFailed()
    if not cmp_password(params["password"], user_data.password_hash):
        raise UserRequestFailed()
    return user_data


def token_endpoint(params):
    access_token_expiry = (
        datetime.datetime.now().timestamp() + CFG()["access_token_expires_in_sec"]
    )
    refresh_token_expiry = (
        datetime.datetime.now().timestamp() + CFG()["refresh_token_expires_in_sec"]
    )
    if "refresh_token" in params:
        refresh_data = jwt.decode(params["refresh_token"], config.oauth_secret)
        if refresh_data["exp"] < datetime.datetime.now().timestamp():
            return {}
        return {
            "access_token": jwt.encode({"exp": access_token_expiry}, config.oauth_secret),
            "refresh_token": jwt.encode({"exp": refresh_token_expiry}, config.oauth_secret),
        }
    try:
        user = get_user_data(params)
        return {
            "access_token": jwt.encode({"exp": access_token_expiry}, config.oauth_secret),
            "refresh_token": jwt.encode({"exp": refresh_token_expiry}, config.oauth_secret),
            "id_token": {"username": user.username},
        }
    except UserRequestFailed:
        return {}
