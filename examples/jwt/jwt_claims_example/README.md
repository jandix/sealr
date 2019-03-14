
# JWT Claims Example

JSON Web Tokens (JWT) *can* contain claims. “Claims are statements about
an entity (typically, the user) and additional data”
(<https://jwt.io/introduction/>). They are expressed as key-value pairs.
There are three different types of claims: registered, public and
private claims. All types of claims are implemented in the same manner,
they only differ in whether and where the claims are registered with the
Internet Assigned Numbers Authority (IANA). For example, the `iss` claim
is a registered claim defined in the JWT standard
[RFC 7519](https://tools.ietf.org/html/rfc7519#page-8) and registered at
IANA. See the [JWT Introduction](https://jwt.io/introduction/) of
[jwt.io](jwt.io) for what those terms exactly mean.

`sealr` allows you to check for the validity of all types of claims
using the `claims` argument of the `sealr::jwt` function.

In this example implementation, we have two filters:

The filter `sealr-jwt` simply checks whether the user is authenticated
and that the issuer claim `iss` is set to `mygreatplumberapi`, the value
we set in the `authenticate` route. The second filter
`sealr-jwt-admin-only` additionally checks whether the user is an admin
by validating that the claim `admin` is `TRUE`.

``` r
# integrate the jwt strategy in a filter
pr$filter("sealr-jwt", function (req, res) {
  # simply call the strategy and forward the request and response
  sealr::jwt(req = req, res = res, secret = secret,
             claims = list(iss = "mygreatplumberapi"))
})

pr$filter("sealr-jwt-admin-only", function (req, res) {
  # simply call the strategy and forward the request and response
  sealr::jwt(req = req, res = res, secret = secret,
             claims = list(iss = "mygreatplumberapi", admin = TRUE))
})
```

We now have two levels of access using filters: routes that are open to
all authenticated users with a JWT issued by `mygreatplumberapi` and
routes that are accessible to admins only. The former requires
`preempt`ing the more restrictive `sealr-jwt-admin-only` filter.

Unfortunately, it is currently not possible to extend this filter-based
authorization mechanism to more than two authorization “levels” because
`plumber` does not allow for preempting more than one filter per route.

## Install the packages

Install the following packages if you haven’t already:

  - sealr
  - httr
  - jose
  - jsonlite

## Run plumber

Source `jwt_claims_example.R` in your R session. This will make the API
available at `localhost:9090`.

## Make some requests

### Authentication route

Using curl, Postman or a similar tool for sending HTTP requests, send a
POST request with the details of one of the two users that are in the
API’s “database” (in this simplified example, a data
frame).

| id | user               | password                                                       | admin | gender |
| -: | :----------------- | :------------------------------------------------------------- | :---- | :----- |
|  1 | <jane@example.com> | $2a\(12\)mIsc5X2lojpDvU31BL5c5u28px7yMhCCz1tE5SDPlYE7EUSM1SGae | TRUE  | woman  |
|  2 | <bob@example.com>  | $2a\(12\)jNFhtw3m.5c8A0iX.WVaT.6Swf4i89QEnRnrnKiAaFV/G460xKCdy | FALSE | man    |

Get the JWT for both
    users:

  - Jane

<!-- end list -->

    curl --data '{"user": "jane@example.com", "password": "12345"}' localhost:9090/authentication
    ["eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MjU2NjAzNSwiYWRtaW4iOnRydWUsImdlbmRlciI6IndvbWFuIiwidXNlcklEIjoxfQ.jNSnrZl3_a3iLsfOuJCB0dIvOOgvpZFXC_v48Odh43A"]

  - Bob

<!-- end list -->

    curl --data '{"user": "bob@example.com", "password": "45678"}' localhost:9090/authentication
    ["eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MjU2NjE1MSwiYWRtaW4iOmZhbHNlLCJnZW5kZXIiOiJtYW4iLCJ1c2VySUQiOjJ9.rPgUcU3m7P8dhWRYKzMVUFqVH2zdzfgQxpPp6j54ZOE"]

### Routes with different authorization levels

Both users can access the `/secret` route because they both have valid
JWT issued by `mygreatplumberapi`. The route `preempt`s the more
restrictive `sealr-jwt-admin-only` filter so even non-admin Bob has
access.

  - Jane

<!-- end list -->

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MjU2NjAzNSwiYWRtaW4iOnRydWUsImdlbmRlciI6IndvbWFuIiwidXNlcklEIjoxfQ.jNSnrZl3_a3iLsfOuJCB0dIvOOgvpZFXC_v48Odh43A" localhost:9090/secret
    
    ["Access to route that requires authentication was successful."]

  - Bob

<!-- end list -->

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MjU2NjE1MSwiYWRtaW4iOmZhbHNlLCJnZW5kZXIiOiJtYW4iLCJ1c2VySUQiOjJ9.rPgUcU3m7P8dhWRYKzMVUFqVH2zdzfgQxpPp6j54ZOE" localhost:9090/secret
    
    ["Access to route that requires authentication was successful."]

In contrast, only Jane can access the `/secret-admin-only`
    route.

  - Jane

<!-- end list -->

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MjU2NjAzNSwiYWRtaW4iOnRydWUsImdlbmRlciI6IndvbWFuIiwidXNlcklEIjoxfQ.jNSnrZl3_a3iLsfOuJCB0dIvOOgvpZFXC_v48Odh43A" localhost:9090/secret-admin-only
    
    ["Access to route that requires admin authorization was successful."]

  - Bob

<!-- end list -->

    curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MjU2NjE1MSwiYWRtaW4iOmZhbHNlLCJnZW5kZXIiOiJtYW4iLCJ1c2VySUQiOjJ9.rPgUcU3m7P8dhWRYKzMVUFqVH2zdzfgQxpPp6j54ZOE" localhost:9090/secret-admin-only
    
    {"status":["Failed."],"code":[401],"message":["Authentication required."]}
