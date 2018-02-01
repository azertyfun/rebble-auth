Authentication system
=====================

Key philosophy
--------------

The Rebble team does *not* want to handle any sensitive user information. This is why we let *authentication providers* check the identity of users for us. At no point do we store information more sensitive than an email address.

Behavior
--------

![Authentication diagram](authentication-scheme.png)

The Rebble Authentication service acts as a pseudo-OAuth2 server. The first-time authentication process is:

1. User is redirected to a webview that points to `https://{rebble-auth}/authorize?redirect_uri={redirect_uri}`;
2. User selects an identity provider they want to use, and are redirected to that provider's login form;
3. Assuming the user accepts to share his profile information with us (name, email), the identity provider calls `https://{rebble-auth}/authorize_callback/{provider}` with an access token or authorization code that can be exchanged for an access token;
4. A unique access token is generated and handed back to the user.

From that point on, and for any future resource access, the process is:

5. The client makes a resource request to a Rebble service, including its stored access token;
6. The service checks the validity of the token with the rebble-auth service;
7. Assuming the token is valid, the service returns the requested resource to the client.

Key settings
------------

You should fill your client ID and secret keys in the `rebblestore-api.json` file.

API
---

### `/authorize?redirect_uri={redirect_uri}`

Shows an HTML page containing links to the supported Identity Provider, as shown in the *Behavior* section.

`redirect_uri` is the URI to which the user's browser will be redirected once the authentication process is completed.

The query parameters `error={error message}` or `access_token={access_token}` will be appended to the `redirect_uri`.

### `/authorize?redirect_uri={redirect_uri}&addProvider&access_token={access_token}`

Shows the same `/authorize` HTML page, but the provider will be added to the already existing account which holds `access_token`.

### `/authorize_callback/{provider}`

Is called back by the identity provider `{provider}`. It will always redirect to the provided `redirect_uri`, unless the URI was lost somehow, in which case an error message will be displayed to the user.

### `/user/client_ids`

Returns the list of SSO client IDs for the frontend to use

Query: Simple `GET` request

Response:
```JSON
{
    "ssos": [
        {
            "name": "google",
            "client_id": "<client id>",
            "discover_uri": "<discover uri>"
        },
        ...
    ]
}
```

### `/user/info`

Request information about the user.

Query:
```JSON
{
    "accessToken": "<access token>",
}
```

Response:
```JSON
{
    "loggedIn": boolean,
    "name": "<name>",
    "errorMessage": "<Error message>"
}
```
If the user is not logged in (the access token is invalid or the associated access token from the SSO has been invalidated), name will be blank and an error message will be provided.  
Otherwise "errorMessage" will be blank.

### `/user/update/name`

Change the logged in user's name. Empty field is allowed.

Query:
```JSON
{
    "accessToken": "<access token>",
    "name": "<Name>"
}
```

Response:
```JSON
{
	"success": boolean,
	"errorMessage": "<error message>"
}
```

### `/user/name/{id}`

Gets user `{id}`'s name

Response:
```JSON
{
    "name": "<name>",
    "errorMessage": "<error message>"
}

If an error occured when retrieving the name (such as invalid id), the name will be blank and the error message will be set accordingly.
```

SQL Structure
-------------

See `rebbleHandlers/admin.go`

* `users` contains the user account information;
* `userSessions` contains all active session (*however, an active session is not necessarily a valid session; the access_token might be invalid);
* `providerSessions` contains all active sessions with identity providers;
* `userLoginLog` contains a log of all user logins for administrative purposes.