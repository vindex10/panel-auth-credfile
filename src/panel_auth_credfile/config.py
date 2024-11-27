from panel.config import config

_CFG = None


def CFG():
    global _CFG
    if _CFG is None:
        _CFG = {}
        _CFG["credentials_file"] = config.oauth_extra_params["credentials_file"]
        _CFG["access_token_expires_in_sec"] = config.oauth_extra_params.get(
            "access_token_expires_in_sec", 180
        )
        _CFG["refresh_token_expires_in_sec"] = config.oauth_extra_params.get(
            "refresh_token_expires_in_sec", 86400
        )
    return _CFG
