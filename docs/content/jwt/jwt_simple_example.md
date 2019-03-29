---
output: 
  md_document:
    preserve_yaml: true
weight: 1
title: JWT Simple Example 
---

In the code [below](#code), you find a small example of how to implement
a JWT strategy in an application.

The application consists of three routes. The first route allows your
users to login and issues a JWT. The second route is an open route that
does not require authentication. The third route requires authentication
using the JWT.

The JWT filter looks like this:

    # integrate the jwt strategy in a filter
    pr$filter("sealr-jwt", function (req, res) {
      # simply call the strategy and forward the request and response
      sealr::authenticate(req = req, res = res, is_authed_fun = sealr::is_authed_jwt,
                          token_location = "header", secret = secret)
    })

:warning: Please change the secret to a super secure secret of your
choice. Please notice that you have to `preempt = c("sealr-jwt")` to
routes that should **not** be protected.

Run the example
---------------

Copy the code from [below](#code) in a new R file and save it under
`jwt_simple_example.R`. In the R console, run:

    plumber::plumb("jwt_simple_example.R")

This will make the API available at `localhost:9090`.

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
<td style="text-align: left;">$2a<span class="math inline">12</span>ivbTpArLsmj9yEadAkSO8enoHLRNyEvnGcogV/SLFXmvaqBYqe2Xu</td>
</tr>
<tr class="even">
<td style="text-align: right;">2</td>
<td style="text-align: left;"><a href="mailto:bob@example.com" class="email">bob@example.com</a></td>
<td style="text-align: left;">$2a<span class="math inline">12</span>GMcha6QyvuzuLMOF4HRXCu9I5OcZRiloLEDy8U7NafXW46F2I1lfy</td>
</tr>
</tbody>
</table>

For example, in curl:

    curl --data '{"user": "jane@example.com", "password": "12345"}' localhost:9090/authentication

gives back the JWT:

    ["eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTE0NDk5NTcsInVzZXJJRCI6MX0.0563N-dcz9zY-NF9DQpUnHIONZRWmZU1rb894xxHcNU"]

**Note**: You might get different JWTs as `jose::jwt_encode_hmac`
automatically adds the time when the JWT was issued as a claim (`iat`
claim). However, those examples should still work because we do not add
an expiration time to the token - something you should definetely
consider for production use cases.

Trying to authenticate with a user that is not in the database fails:

    curl --data '{"user": "drake@example.com", "password": "10111213"}' localhost:9090/authentication

    {"status":["Failed."],"code":[401],"message":["User or password wrong."]}

### Route without required authentication

Everyone can access the `/` route because it does not require
authentication - the `sealr-jwt` filter is `preempt`ed for this route:

    curl localhost:9090
    ["Access to route without authentication was successful."]

### Route with authentication

Trying to access the `/secret` route without a JWT fails because it goes
through the `sealr-jwt` filter where the `sealr::jwt` function will
check for the correct authentication details - in this case a valid JWT
in the Authorization header.

    curl localhost:9090/secret

    {"status":["Failed."],"code":[401],"message":["Authentication required."]}

Use the JWT obtained with the first curl command to make an
authenticated request to this route.

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTE0NDk5NTcsInVzZXJJRCI6MX0.0563N-dcz9zY-NF9DQpUnHIONZRWmZU1rb894xxHcNU" localhost:9090/secret
    ["Access to route requiring authentication was successful."]

Code
----

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

    # define your super secret
    secret <- "3ec9aaf4a744f833e98c954365892583"

    # integrate the jwt strategy in a filter
    pr$filter("sealr-jwt", function (req, res) {
      # simply call the strategy and forward the request and response
      sealr::authenticate(req = req, res = res, is_authed_fun = sealr::is_authed_jwt,
                          token_location = "header", secret = secret)
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

      # return jwt as response
      return(jwt = jwt)
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
