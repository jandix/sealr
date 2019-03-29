---
title: JWT Cookie Example
weight: 3
output: 
  md_document:
    preserve_yaml: true
---

Instead of requiring the user to send the JWT back in the HTTP
Authorization header, you can also use a cookie in the browser of the
API user to store the JWT. This way, the user does not have to remember
to send the JWT in the Authorization header.

Example implementation
----------------------

In this example, we use an encrypted cookie to store the JWT. You can
find the full code for this example at the [end of this page](#code). In
order to do this, we register an encrypted session cookie ([see plumber
docs](https://www.rplumber.io/docs/rendering-and-output.html#encrypted-cookies)):

    # define a new plumber router
    pr <- plumber::plumber$new()
    # register cookie
    pr$registerHooks(plumber::sessionCookie(key = "EPCGoaMO9dIxIEPoOjOL4sjL4U6w0GQ5", name = "token"))

In the `authentication` route, we then can set the JWT in the cookie.
Note that we do not return the JWT to the user because the JWT will be
transferred in the cookie instead.

    pr$handle("POST", "/authentication", function (req, res, user = NULL, password = NULL) {
      # ...
      # ...
      # set cookie
      req$session$token <- jwt
      return()
    })

The filter looks the same as in the simple example except that we have
to change the `token_location` parameter to `"cookie"` instead of
`"header"`.

    # integrate the jwt strategy in a filter
    pr$filter("sealr-jwt", function (req, res) {
      # simply call the strategy and forward the request and response
      # please change the secret
      sealr::authenticate(req = req, res = res, is_authed_fun = sealr::is_authed_jwt,
                          token_location = "cookie", secret = secret)
    })

:warning: Please change the secret to a super secure secret of your
choice. Please notice that you have to `preempt = c("sealr-jwt")` to
routes that should **not** be protected.

Run the example
---------------

Copy the code from [below](#code) in a new R file and save it under
`jwt_cookie_example.R`. In the R console, run:

    plumber::plumb("jwt_cookie_example.R")

In order to run this example, you need the following packages installed:

-   sealr
-   plumber
-   httr
-   jose
-   jsonlite

### Get authentication

Using curl, Postman or a similar tool for sending HTTP requests, send a
POST request with the details of one of the two users that are in the
API’s “database” (in this simplified example, a data frame).

<table>
<colgroup>
<col style="width: 3%" />
<col style="width: 20%" />
<col style="width: 75%" />
</colgroup>
<thead>
<tr class="header">
<th style="text-align: right;">id</th>
<th style="text-align: left;">user</th>
<th style="text-align: left;">password</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="text-align: right;">1</td>
<td style="text-align: left;"><a href="mailto:jane@example.com" class="email">jane@example.com</a></td>
<td style="text-align: left;">$2a<span class="math inline">12</span>rj8TddYRy6fPXxbfBZjovO5DdLxm5jVhWCdz5un2Wi6v47YSKc2oe</td>
</tr>
<tr class="even">
<td style="text-align: right;">2</td>
<td style="text-align: left;"><a href="mailto:bob@example.com" class="email">bob@example.com</a></td>
<td style="text-align: left;">$2a<span class="math inline">12</span>toswpnhB3L5IOzd4JWs4MefiBx5OxVQNJ5cMg/aFohM.blHRHttNm</td>
</tr>
</tbody>
</table>

For example, in curl:

**Note**: You might get different encrypted JWTs in your
`cookies_jane.txt` as `jose::jwt_encode_hmac` automatically adds the
time when the JWT was issued as a claim (`iat` claim).

    curl  --cookie-jar cookies_jane.txt --data '{"user": "jane@example.com", "password": "12345"}' localhost:9090/authentication

The `--cookie-jar` argument will store the cookie in a plain-text file
in your current directory called `cookies_jane.txt`.

If you inspect this file (e.g. using `cat cookies_jane.txt`), you should
see something like this:

    # Netscape HTTP Cookie File
    # https://curl.haxx.se/docs/http-cookies.html
    # This file was generated by libcurl! Edit at your own risk.

    localhost   FALSE   /   FALSE   0   token   R/cOKStnaCrwojcbL4Uk1602scv7ln9PClDYO2LlfHd0zYtd+vYrGB6oTX7wvpp5hmipFxqnQ0FDwEdz1H7IjCr6KCxxUHnpWu8r0IjCA4zLHbJz/i5npGe16Ei+OhbOGbluT/An+0GnfzXsna4q4vHoB2P+GkUPZL3Xe7tZxIX+UHSk005tX89NcSLpVy6J

The token is the gibberish part at the end. It is indeed the JWT but it
is encrypted and hence does not *look* like a JWT.

Trying to get a token cookie for a user that is not in the database of
course fails:

    curl --cookie-jar cookies_drake.txt --data '{"user": "drake@example.com", "password": "10111213"}' localhost:9090/authentication

    {"status":["Failed."],"code":[401],"message":["User or password wrong."]}

Route without required authentication
-------------------------------------

Everyone can access the `/` route because it does not require
authentication - the `sealr-jwt` filter is `preempt`ed for this route:

    curl localhost:9090
    ["Access to route without authentication was successful."]

Route with required authentication
----------------------------------

Trying to access the `/secret` route without a valid cookie fails
because it goes through the `sealr-jwt` filter where the `sealr::jwt`
function will check for the correct authentication details - in this
case a valid JWT in `token` cookie.

    curl localhost:9090/secret

    {"status":["Failed."],"code":[401],"message":["Authentication required."]}

But if you add the cookies for Jane to the request, authentication is
successful.

    curl --cookie cookies_jane.txt localhost:9090/secret

    ["Access to route requiring authentication was successful."]

Code {code}
-----------

    # define a user database
    # you should probably use a SQL database instead of data frames
    users <- data.frame(id       = integer(),
                        name     = character(),
                        password = character(),
                        stringsAsFactors = FALSE)

    # create test user
    users <- rbind(users, data.frame(id       = 1,
                                     user     = "jane@example.com",
                                     password = bcrypt::hashpw("12345"),
                                     stringsAsFactors = FALSE))
    users <- rbind(users, data.frame(id       = 2,
                                     user     = "bob@example.com",
                                     password = bcrypt::hashpw("45678"),
                                     stringsAsFactors = FALSE))

    # define a new plumber router
    pr <- plumber::plumber$new()
    # register cookie
    pr$registerHooks(plumber::sessionCookie(key = "EPCGoaMO9dIxIEPoOjOL4sjL4U6w0GQ5", name = "token"))

    # define your super secret for hmac
    secret <- "3ec9aaf4a744f833e98c954365892583"

    # integrate the jwt strategy in a filter
    pr$filter("sealr-jwt", function (req, res) {
      # simply call the strategy and forward the request and response
      sealr::authenticate(req = req, res = res, is_authed_fun = sealr::is_authed_jwt,
                          token_location = "cookie", secret = secret)
    })

    # define authentication route to issue web tokens (exclude "sealr-jwt" filter using preempt)
    pr$handle("POST", "/authentication", function (req, res, user = NULL, password = NULL) {

      # check if user provided credentials
      if (is.null(user) || is.null(password)) {
        res$status <- 404
        return(list(status="Failed.",
                    code=404,
                    message="Please return password or username."))
      }

      # find user in database
      index <- match(user, users$user)

      # check if user exist
      if (is.na(index)) {
        res$status <- 401
        return(list(status="Failed.",
                    code=401,
                    message="User or password wrong."))
      }

      # check if password is correct
      if (!bcrypt::checkpw(password, users$password[index])){
        res$status <- 401
        return(list(status="Failed.",
                    code=401,
                    message="User or password wrong."))
      }

      # define jwt payload
      # information about the additional fields can be found at
      # https://tools.ietf.org/html/rfc7519#section-4.1
      payload <- jose::jwt_claim(userID = users$id[index])

      # convert secret to bytes
      secret_raw <- charToRaw(secret)

      # encode token using the secret
      jwt <- jose::jwt_encode_hmac(payload, secret = secret_raw)

      # set cookie
      req$session$token <- jwt
      return()
    }, preempt = c("sealr-jwt"))

    # define test route without authentication  (exclude "sealr-jwt" filter using preempt)
    pr$handle("GET", "/", function (req, res) {
      return("Access to route without authentication was successful.")
    }, preempt = c("sealr-jwt"))



    # define test route with authentication
    pr$handle("GET", "/secret", function (req, res) {
      return("Access to route requiring authentication was successful.")
    })

    # start API server
    pr$run(host = "0.0.0.0", port = 9090)