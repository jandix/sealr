
<!-- README.md is generated from README.Rmd. Please edit that file -->
sealr
=====

[![Build Status](https://travis-ci.org/jandix/sealr.svg?branch=master)](https://travis-ci.org/jandix/sealr) [![codecov](https://codecov.io/gh/jandix/sealr/branch/master/graph/badge.svg)](https://codecov.io/gh/jandix/sealr)

The goal of sealr is to provide multiple authentication and authorization strategies for [plumber](https://www.rplumber.io/) by using [filters](https://www.rplumber.io/docs/routing-and-input.html#filters). In doing so, we hope to make best practices in authentication easy to implement for the R community. The package is inspired by the amazing [passport.js](http://www.passportjs.org/) library for Node.js.

Installation
------------

Currently, the package is under development. Please feel free to contribute to the package. You can install and use the package using `devtools`.

``` r
devtools::install_github("jandix/sealr")
```

Contribute
----------

We are still at the very beginning of the package and we welcome any support and contribution. Below you find a list with possible authentication strategies that you could implement. The list is not complete and can be expanded with your suggestions.

#### Possible Strategies

-   \[ \] Bearer Token
-   \[ \] Sessions
-   \[ \] Twitter OAuth
-   \[ \] Facbook OAuth
-   \[ \] Google OAuth

Testing
-------

You can use curl for testing purposes. Unfortuentaly, curl fastly becomes quite complicated if you want to add a body, parameters and unique headers. Therefore, we recommend to use [Postman](https://www.getpostman.com/) for larger, more complicated projects.

JSON Web Tokens (JWT)
---------------------

"JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties." (jwt.io)

The JWT stratgey allows to use JWT to secure your endpoints. A great introduction to JWT can be found [here](https://jwt.io/introduction/). It can be used to secure REST APIs without sessions. It is considered to be stateless. Below you find a small introduction to implement a JWT strategy in your application.

The application consists of three routes. The first route allows your users to login and issues a JWT. The second route is an open route that return the first one hundred entries of the iris dataset. The third route requires authentication using the JWT and return the last 50 entries of the iris dataset.

You can use the curl statement below to test your application:

    curl -H "Authorization: Bearer <JWT_TOKEN>" localhost:9090/secret

:warning: Please change the secret to a super secure secret of your choice. Please notice that you have to `preempt = c("sealr-jwt")` to routes that should **not** be protected.

``` r
# define a new plumber router
pr <- plumber::plumber$new()

# define your super secret
# please change the key
secret <- "3ec9aaf4a744f833e98c954365892583"

# integrate the jwt strategy in a filter
pr$filter("sealr-jwt", function (req, res) {
  # simply call the strategy and forward the request and response
  sealr::jwt(req = req, res = res, secret = secret)
})

# define authentication route to issue web tokens (exclude "sealr-jwt" filter using preempt)
pr$handle("POST", "/authentication", function (req, user = NULL, password = NULL) {
  
  # check if user provided credentials
  if (is.null(user) || is.null(password)) {
    return(list(status="Failed.",
                code=404,
                message="Please return password or username."))
  }
  
  # here you check whether user exists and password is correct
  # please use bcrypt to hash passwords
  
  # define jwt payload
  # information about the additional fields can be found at 
  # https://tools.ietf.org/html/rfc7519#section-4.1
  payload <- jose::jwt_claim(userID = 12812622182)
  
  # convert secret to bytes
  secret <- charToRaw(secret)
  
  # encode token using the secret 
  jwt <- jose::jwt_encode_hmac(payload, secret = secret)
  
  # return jwt as response
  return(jwt = jwt)
}, preempt = c("sealr-jwt"))

# define test route without authentication  (exclude "sealr-jwt" filter using preempt)
pr$handle("GET", "/", function (req, res) {
  return(iris[1:100, ])
}, preempt = c("sealr-jwt"))



# define test route with authentication
pr$handle("GET", "/secret", function (req, res) {
  return(iris[101:150, ])
})

# start API server
pr$run(host="0.0.0.0", port=9090)
```

Warranity Notice
----------------

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
