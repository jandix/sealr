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
that contains:

-   access token that is valid for 1 hour (3600 seconds)
-   refresh token
-   id token

Depending on your browser, it should look something like this:

![google return](images/google_oauth_return.png)

define a new plumber router
---------------------------

    pr <- plumber::plumber$new()

    pr$handle("GET", "/", function (req, res, code = NULL) {

    })

define authentication route to issue web tokens (exclude “sealr-jwt” filter using preempt)
------------------------------------------------------------------------------------------

    pr$handle("GET", "/authentication", function (req, res) {
      url <- "https://accounts.google.com/o/oauth2/v2/auth"

      query <- list(client_id = "62291147513-pubf19de15prks9p2eij7hloteug5h5d.apps.googleusercontent.com",
                    redirect_uri = "http://localhost:9090/authentication/redirect",
                    scope = "https://www.googleapis.com/auth/userinfo.profile",
                    response_type = "code")
      auth_url <- httr::parse_url(url = url)
      auth_url$query <- query
      auth_url <- httr::build_url(auth_url)
      res$status <- 301
      res$setHeader("Location", auth_url)
      return()
    })

define authentication route to issue web tokens (exclude “sealr-jwt” filter using preempt)
------------------------------------------------------------------------------------------

    pr$handle("GET", "/authentication/redirect", function (req, res, code = NULL, error = NULL) {
      token_url <- "https://www.googleapis.com/oauth2/v4/token"
      body <- list(
        code = code,
        client_id = "62291147513-pubf19de15prks9p2eij7hloteug5h5d.apps.googleusercontent.com",
        client_secret = "0iE21iyz1htfHPtOw21zWcw6",
        redirect_uri = "http://localhost:9090/authentication/redirect",
        grant_type = "authorization_code"
      )
      response <- httr::POST(token_url, body = body)
      parsed_response <- jsonlite::fromJSON(httr::content(response, type = "text"))
      return(parsed_response)
    })

start API server
----------------

    pr$run(host="0.0.0.0", port=9090)
