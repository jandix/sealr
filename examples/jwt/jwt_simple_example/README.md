
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
|  1 | <jane@example.com> | $2a\(12\)XFpypd/8k4qMhduUkPJPuuaZvguMhz5Z7rnTimuiwFRYv1FuxZ/06 |
|  2 | <bob@example.com>  | $2a\(12\)onYHlhOASz84ZJPN4pN2sOD7LkRdlqvqVgsn1JrE6Eqb1GbFeeT/2 |

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

This request gives back the first 100 rows of the iris dataset.

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

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTE0NDk5NTcsInVzZXJJRCI6MX0.0563N-dcz9zY-NF9DQpUnHIONZRWmZU1rb894xxHcNU localhost:9090/secret

This request gives back rows 100-150 of the iris dataset.