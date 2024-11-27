# Panel Auth Credfile

Authenticate user in Panel using a credentials file.

* Passwords are hashed in the credentials file, so they can't leak.
* This package installs an executable script `panel-auth-credfile`. Use it to generate password hash.
* Provide path to the credentials file using PANEL env var:
  `PANEL_OAUTH_EXTRA_PARAMS = '{"credentials_file": "/path/to/panel_credentials.json"}'`
* Specify auth provider: `PANEL_OAUTH_PROVIDER = "credfile"`
* Metadata fields are available further for authorization inside panel routes.
    Underscored fields are not stored in memory, and droped at the parsing time.


Credfile example (you can store the original password as underscored field if you want):


```
[
    {"username": "user",
     "password_hash": "$2b$12$57HQmMCM2T0tFz5gg0FAteYoDZxQOZeskT7rATBi2xlUhHCcO5N8m",
     "metadata": {"role": "test_user", "_original_password": "password"}}
]
```
