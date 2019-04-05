---
output: 
  md_document:
    preserve_yaml: true
weight: 2
title: JWT Claims Example
---

JSON Web Tokens (JWT) *can* contain claims. “Claims are statements about
an entity (typically, the user) and additional data”
(<https://jwt.io/introduction/>). They are expressed as key-value pairs.

There are three different types of claims: registered, public and
private claims. All types of claims are implemented in the same manner,
they only differ in whether and where the claims are registered with the
Internet Assigned Numbers Authority (IANA). For example, the `iss` claim
is a registered claim defined in the JWT standard [RFC
7519](https://tools.ietf.org/html/rfc7519#page-8) and registered at
IANA. See the [JWT Introduction](https://jwt.io/introduction/) of
[jwt.io](jwt.io) for more details.

`sealr` allows you to check for the validity of all types of claims in a
given JWT using the `claims` argument of the `sealr::is_authed_jwt`
function.

In this example implementation (see full code [below](#code)), we have
two filters:

The filter `sealr-jwt` simply checks whether the user is authenticated
and that the issuer claim `iss` is set to `mygreatplumberapi`, the value
we set in the `authentication` route. The second filter
`sealr-jwt-admin-only` additionally checks whether the user is an admin
by validating that the claim `admin` is `TRUE`.

    # integrate the jwt strategy in a filter
    pr$filter("sealr-jwt", function (req, res) {
      # simply call the strategy and forward the request and response
      sealr::authenticate(req = req, res = res, is_authed_fun = is_authed_jwt, secret = secret,
                 claims = list(iss = "mygreatplumberapi"))
    })

    pr$filter("sealr-jwt-admin-only", function (req, res) {
      # simply call the strategy and forward the request and response
      sealr::authenticate(req = req, res = res, is_authed_fun = is_authed_jwt, secret = secret,
                 claims = list(iss = "mygreatplumberapi", admin = TRUE))
    })

We now have two levels of access using filters: routes that are open to
all authenticated users with a JWT issued by `mygreatplumberapi` and
routes that are accessible to admins only. The former requires
`preempt`ing the more restrictive `sealr-jwt-admin-only` filter.

Unfortunately, it is currently not possible to extend this filter-based
authorization mechanism to more than two authorization “levels” because
`plumber` does not allow for preempting more than one filter per route.
This problem is on the radar of the `plumber` team and they’ll provide
the opportunity to impose filters on specific endpoints in the future
(kind of “reverting” the `preempt` logic). See [this plumber
issue](https://github.com/trestletech/plumber/issues/108).

As a workaround, you could put your authentication / authorization
checks in the individual endpoints. In this case, use `is_authed_*`
functions instead of the `authenticate` wrapper.

Run the example
---------------

Copy the code from [below](#code) in a new R file and save it under
`jwt_claims_example.R`. In the R console, run:

    plumber::plumb("jwt_claims_example.R")

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
<col style="width: 18%" />
<col style="width: 64%" />
<col style="width: 6%" />
<col style="width: 7%" />
</colgroup>
<thead>
<tr class="header">
<th style="text-align: right;">id</th>
<th style="text-align: left;">user</th>
<th style="text-align: left;">password</th>
<th style="text-align: left;">admin</th>
<th style="text-align: left;">gender</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="text-align: right;">1</td>
<td style="text-align: left;"><a href="mailto:jane@example.com" class="email">jane@example.com</a></td>
<td style="text-align: left;">$2a<span class="math inline">12</span>OIUZboRrNamFXs0A9cNfuu82AHBQ51qdhSE1H5CL23gbRaW1vODyK</td>
<td style="text-align: left;">TRUE</td>
<td style="text-align: left;">woman</td>
</tr>
<tr class="even">
<td style="text-align: right;">2</td>
<td style="text-align: left;"><a href="mailto:bob@example.com" class="email">bob@example.com</a></td>
<td style="text-align: left;">$2a<span class="math inline">12</span>D7TMyxozksU.A642T3seyOy5tKXnV4yxftZ9DPxAXQtzDoqU9R1mS</td>
<td style="text-align: left;">FALSE</td>
<td style="text-align: left;">man</td>
</tr>
</tbody>
</table>

Get the JWT for both users:

-   Jane

<!-- -->

    curl --data '{"user": "jane@example.com", "password": "12345"}' localhost:9090/authentication
    ["eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NjE0NiwiYWRtaW4iOnRydWUsImdlbmRlciI6IndvbWFuIiwidXNlcklEIjoxfQ.AZqJFuXZkjwKbnULHfJVmBapFhZpBgLIUuX7HOJAUhU"]

-   Bob

<!-- -->

    curl --data '{"user": "bob@example.com", "password": "45678"}' localhost:9090/authentication
    ["eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NTgzNCwiYWRtaW4iOmZhbHNlLCJnZW5kZXIiOiJtYW4iLCJ1c2VySUQiOjJ9.WjRD5aIaqgApWJ-bf0VosbMZ3ovDyvRVvYug-5egL8s"]

**Note**: You might get different JWTs as we also add the time when the
token was issued as a claim (`iat`). However, those examples should
still work because we do not add an expiration time to the token -
something you should definetely consider for production use cases.

### Route with simple authentication

Both users can access the `/secret` route because they both have valid
JWT issued by `mygreatplumberapi`. The route `preempt`s the more
restrictive `sealr-jwt-admin-only` filter so even non-admin Bob has
access.

-   Jane

<!-- -->

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NTc3NSwiYWRtaW4iOnRydWUsImdlbmRlciI6IndvbWFuIiwidXNlcklEIjoxfQ.FXLTGUcsn8yuiS7VqoGEjw94zQsmO6sYdWJeLeS-PhE" localhost:9090/secret

    ["Access to route that requires authentication was successful."]

-   Bob

<!-- -->

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NTgzNCwiYWRtaW4iOmZhbHNlLCJnZW5kZXIiOiJtYW4iLCJ1c2VySUQiOjJ9.WjRD5aIaqgApWJ-bf0VosbMZ3ovDyvRVvYug-5egL8s" localhost:9090/secret

    ["Access to route that requires authentication was successful."]

### Route with admin-only authorization

In contrast, only Jane can access the `/secret-admin-only` route.

-   Jane

<!-- -->

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NTc3NSwiYWRtaW4iOnRydWUsImdlbmRlciI6IndvbWFuIiwidXNlcklEIjoxfQ.FXLTGUcsn8yuiS7VqoGEjw94zQsmO6sYdWJeLeS-PhE" localhost:9090/secret-admin-only

    ["Access to route that requires admin authorization was successful."]

-   Bob

<!-- -->

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NTgzNCwiYWRtaW4iOmZhbHNlLCJnZW5kZXIiOiJtYW4iLCJ1c2VySUQiOjJ9.WjRD5aIaqgApWJ-bf0VosbMZ3ovDyvRVvYug-5egL8s" localhost:9090/secret-admin-only

    {"status":["Failed."],"code":[401],"message":["Authentication required."]}

Code
----

    # define a user database
    # you should probably use a SQL database instead of data frames
    users <- data.frame(id       = integer(),
                        name     = character(),
                        password = character(),
                        admin = logical(),
                        gender = character(),
                        stringsAsFactors = FALSE)

    # create test user
    users <- rbind(users, data.frame(id       = 1,
                                     user     = "jane@example.com",
                                     password = bcrypt::hashpw("12345"),
                                     admin = TRUE,
                                     gender = "woman",
                                     stringsAsFactors = FALSE))
    users <- rbind(users, data.frame(id       = 2,
                                     user     = "bob@example.com",
                                     password = bcrypt::hashpw("45678"),
                                     admin = FALSE,
                                     gender = "man",
                                     stringsAsFactors = FALSE))

    # define a new plumber router
    pr <- plumber::plumber$new()

    # define your super secret
    secret <- "3ec9aaf4a744f833e98c954365892583"

    # integrate the jwt strategy in a filter
    pr$filter("sealr-jwt", function (req, res) {
      # simply call the strategy and forward the request and response
      sealr::authenticate(req = req, res = res, is_authed_fun = is_authed_jwt,
                          secret = secret, claims = list(iss = "mygreatplumberapi"))
    })

    # filter that checks whether the user is an admin
    pr$filter("sealr-jwt-admin-only", function (req, res) {
      # simply call the strategy and forward the request and response
      sealr::authenticate(req = req, res = res, is_authed_fun = is_authed_jwt,
                          secret = secret, claims = list(iss = "mygreatplumberapi", admin = TRUE))
    })

    # define authentication route to issue web tokens (exclude "sealr-jwt" filter using preempt)
    pr$handle("POST", "/authentication", function (req, res, user = NULL, password = NULL) {

      # check if user provided credentials
      if (is.null(user) || is.null(password)) {
        res$status <- 404
        return(list(status="Failed.",
                    code=404,
                    message="Please specify password or username."))
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
      payload <- jose::jwt_claim(iss = "mygreatplumberapi", # registered claim
                                 iat = as.numeric(Sys.time()), # registered claim
                                 admin = users$admin[index],
                                 gender = users$gender[index], # a public claim
                                 userID = users$id[index]) # private claim

      # convert secret to bytes
      secret <- charToRaw(secret)

      # encode token using the secret
      jwt <- jose::jwt_encode_hmac(payload, secret = secret)

      # return jwt as response
      return(jwt = jwt)
    }, preempt = c("sealr-jwt"))



    # define test route with authentication
    pr$handle("GET", "/secret", function (req, res) {
      return("Access to route that requires authentication was successful.")
    }, preempt = "sealr-jwt-admin-only")

    # define test route with authentication
    pr$handle("GET", "/secret-admin-only", function (req, res) {
      return("Access to route that requires admin authorization was successful.")
    })

    # start API server
    pr$run(host = "0.0.0.0", port = 9090)
