
# JWT Simple Example

## JSON Web Tokens

“JSON Web Tokens are an open, industry standard RFC 7519 method for
representing claims securely between two parties.” (jwt.io)

The JWT stratgey allows to use JSON Web Tokens (JWT) to secure your
plumber endpoints. A great introduction to JWT can be found
[here](https://jwt.io/introduction/). JWT can be used to secure REST
APIs without sessions. They are considered to be stateless. In
`jwt_simple_example.R`, you find a small example of how to implement a
JWT strategy in your application.

The application consists of three routes. The first route allows your
users to login and issues a JWT. The second route is an open route that
does not require authentication. The third route requires authentication
using the JWT.

The JWT filter looks like this:

``` r
# integrate the jwt strategy in a filter
pr$filter("sealr-jwt", function (req, res) {
  # simply call the strategy and forward the request and response
  # please change the secret
  sealr::jwt(req = req, res = res, secret = "3ec9aaf4a744f833e98c954365892583")
})
```

:warning: Please change the secret to a super secure secret of your
choice. Please notice that you have to `preempt = c("sealr-jwt")` to
routes that should **not** be protected.

## Install the packages

Install the following packages if you haven’t already:

  - sealr
  - httr
  - jose
  - jsonlite

## Run plumber

Source `jwt_simple_example.R` in your R session. This will make the API
available at `localhost:9090`.

## Make some requests

### Authentication route

Using curl, Postman or a similar tool for sending HTTP requests, send a
POST request with the details of one of the two users that are in the
API’s “database” (in this simplified example, a data
frame).

| id | user               | password                                                       |
| -: | :----------------- | :------------------------------------------------------------- |
|  1 | <jane@example.com> | $2a$12$5JnYESvwmKnyti.X6l7cuOMY78Ourinc4ujutZnQiFb0jNh1X4pH2   |
|  2 | <bob@example.com>  | $2a\(12\)zDT7.kkN0ZYjO2iUVAKzqeJ40TeGlx7jb62VoOnKfQNqoznaawidG |

For example, in
    curl:

    curl --data '{"user": "jane@example.com", "password": "12345"}' localhost:9090/authentication

gives back the
    JWT:

    ["eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTE0NDk5NTcsInVzZXJJRCI6MX0.0563N-dcz9zY-NF9DQpUnHIONZRWmZU1rb894xxHcNU"]

Trying to authenticate with a user that is not in the database
    fails:

    curl --data '{"user": "drake@example.com", "password": "10111213"}' localhost:9090/authentication

    {"status":["Failed."],"code":[401],"message":["User or password wrong."]}

### Routes with and without authentication

Everyone can access the `/` route because it does not require
authentication - the `sealr-jwt` filter is `preempt`ed for this route:

    curl localhost:9090
    ["Access to route without authentication was successful."]

Trying to access the `/secret` route without a JWT fails because it goes
through the `sealr-jwt` filter where the `sealr::jwt` function will
check for the correct authentication details - in this case a valid JWT
in the Authorization
    header.

    curl localhost:9090/secret

    {"status":["Failed."],"code":[401],"message":["Authentication required."]}

Use the JWT obtained with the first curl command to make an
authenticated request to this
    route.

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTE0NDk5NTcsInVzZXJJRCI6MX0.0563N-dcz9zY-NF9DQpUnHIONZRWmZU1rb894xxHcNU" localhost:9090/secret
    ["Access to route requiring authentication was successful."]
