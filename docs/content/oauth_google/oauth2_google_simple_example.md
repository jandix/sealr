---
output: 
  md_document:
    preserve_yaml: true
title: OpenID Connect Google Simple Example
weight: 1
---

Run the example
---------------

### Obtain Google OAuth credentials

In order to run this example, you need to obtain OAuth2.0 credentials
for your plumber API so that Google later knows that it is
authenticating the user to a legitimate application. For this, create a
new **project** in the [Google API
Console](https://console.developers.google.com/) - you may need to
authorize your Google account first if you are not yet a user of
Google’s developer platform.

Once you have created your project, follow the instructions on “Obtain
OAuth 2.0 credentials”
[here](https://developers.google.com/identity/protocols/OpenIDConnect).
When you have to select the application type, select “Other”. Store the
client ID and the client secret as environment variables in your R
session using the following commands.

    Sys.setenv("GOOGLE_CLIENT_ID" = "yourid")
    Sys.setenv("GOOGLE_CLIENT_SECRET" = "yoursecret")

This will make the client and secret available for your *current* R
session. If you want to make them available beyond your current session,
use `usethis::edit_r_environ` and add them in the file that opens like
this:

    GOOGLE_CLIENT_ID="yourid"
    GOOGLE_CLIENT_SECRET="yoursecret"

Save and close the file.

### Run the plumber API

Copy the code from [below](#code) in a new R file and save it under
`oauth2_google_simple_example.R`. In the R console, run:

    plumber::plumb("oauth2_google_simple_example.R")

This will make the API available at `localhost:9090`.

In order to run this example, you need the following packages installed:

-   sealr
-   plumber
-   httr
-   jose
-   jsonlite

Authenticate yourself to the plumber API
----------------------------------------

Open your browser and enter `http://localhost:9090/authentication/` in
the address bar. You’ll be redirected to Google. Authorize your
application / plumber API. You’ll be again redirected to a JSON response
that, depending on your browser, should look something like this (tokens
are blacked out):

![google return](/sealr/docs/images/google_oauth_return.png)

It contains:

-   `access_token`: the token you would need if you wanted to access any
    of Google’s APIs in your plumber API. If you only use Google to
    **authenticate** users, this will not be necessary.
-   `expires_in`: how long the access token is valid in seconds. This
    value is set by Google. In this case, the access token is valid for
    one hour.
-   `refresh_token`: the token you can could to refresh your access
    token. We have not implemented the refresh logic in this example
    though.
-   `scope`: the scope your plumber API requested to authorize from the
    user. In this example, we only requested the “userinfo.profile”
    scope.
-   `token_type`: type of token. This will always be “Bearer”. Prepend
    this to your HTTP Authorization Header (see below).
-   `id_token`: The ID token. A JSON Web Token (see section on JWT) that
    contains information about the identify of the user. This token is
    signed by Google. **This is the token you send in the HTTP
    Authorization header** (see below).

See also the explanation of the return values on [Google’s OpenID
Connect
website](https://developers.google.com/identity/protocols/OpenIDConnect#authuser).

Send an authenticated request
-----------------------------

Open a terminal and enter the following command, replacing the
YOUR\_ID\_TOKEN with the `id_token` from your response.

    curl -H "Authorization: Bearer YOUR_ID_TOKEN" localhost:9090/secret

The ID token will be quite long, so maybe first edit this command in
your text editor of choice before copying it to the terminal. Hit enter.

You should get back:

    {"message":["Successfully accessed the secret endpoint."]}

Code
----

    # define contant variables
    CLIENT_ID <- Sys.getenv("GOOGLE_CLIENT_ID")
    CLIENT_SECRET <- Sys.getenv("GOOGLE_CLIENT_SECRET")

    # get the discovery document with the required URLs
    response <- httr::GET("https://accounts.google.com/.well-known/openid-configuration")
    discovery_document <- jsonlite::fromJSON(httr::content(response, type = "text", encoding = "UTF-8"))

    # define a new plumber router
    pr <- plumber::plumber$new()

    # integrate the google strategy in a filter
    pr$filter("sealr-oauth2-google", function (req, res) {
      # simply call the strategy and forward the request and response
      sealr::authenticate(req = req, res = res, token_location = "header",
                          is_authed_fun = sealr::is_authed_oauth2_google, client_id = CLIENT_ID)
    })

    # define authentication route to issue web tokens (exclude "sealr-google" filter using preempt)
    pr$handle("GET", "/authentication", function (req, res) {
      url <- discovery_document$authorization_endpoint

      query <- list(client_id = CLIENT_ID,
                    redirect_uri = "http://localhost:9090/authentication/redirect",
                    scope = "https://www.googleapis.com/auth/userinfo.profile",
                    response_type = "code")
      auth_url <- httr::parse_url(url = url)
      auth_url$query <- query
      auth_url <- httr::build_url(auth_url)
      res$status <- 301
      res$setHeader("Location", auth_url)
      return()
    }, preempt = c("sealr-oauth2-google"))

    # define authentication route to issue web tokens (exclude "sealr-google" filter using preempt)
    pr$handle("GET", "/authentication/redirect", function (req, res, code = NULL, error = NULL) {
      token_url <- discovery_document$token_endpoint
      body <- list(
        code = code,
        client_id = CLIENT_ID,
        client_secret = CLIENT_SECRET,
        redirect_uri = "http://localhost:9090/authentication/redirect",
        grant_type = "authorization_code"
      )
      response <- httr::POST(token_url, body = body)
      parsed_response <- jsonlite::fromJSON(httr::content(response, type = "text"))
      return(parsed_response)
    }, preempt = c("sealr-oauth2-google"))

    # protected path
    pr$handle("GET", "/secret", function (req, res) {
      list(message = "Successfully accessed the secret endpoint.")
    })

    # start API server
    pr$run(host="0.0.0.0", port=9090)
