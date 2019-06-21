
# Strategies


## JSON Web Tokens (JWT)

### Introduction 

"JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties." (jwt.io)

The JWT stratgey allows to use JSON Web Tokens (JWT) to secure your plumber endpoints. A great introduction to JWT can be found [here](https://jwt.io/introduction/). JWT can be used to secure REST APIs without sessions. They are considered to be stateless although they can also be used as stateful session tokens. 


JSON Web Tokens (JWT) *can* contain claims. "Claims are statements about an entity (typically, the user) and additional data" ([https://jwt.io/introduction/](https://jwt.io/introduction/)). They are expressed as key-value pairs.

There are three different types of claims: registered, public and private claims. All types of claims are implemented in the same manner, they only differ in whether and where the claims are registered with the Internet Assigned Numbers Authority (IANA). For example, the `iss` claim is a registered claim defined in the JWT standard [RFC 7519](https://tools.ietf.org/html/rfc7519#page-8) and registered at IANA. See the [JWT Introduction](https://jwt.io/introduction/) of [jwt.io](jwt.io) for more details.

`sealr` allows you to check for the validity of all types of claims in a given JWT using the `claims` argument of the `sealr::is_authed_jwt` function. 

### Simple Example


In the code [below](#code), you find a small example of how to implement a JWT strategy in an application.  

The application consists of three routes. The first route allows your users to login and issues a JWT. The second route is an open route that does not require authentication. The third route requires authentication using the JWT.

The JWT filter looks like this:


```r
# integrate the jwt strategy in a filter
pr$filter("sealr-jwt", function (req, res) {
  # simply call the strategy and forward the request and response
  sealr::authenticate(req = req, res = res, is_authed_fun = sealr::is_authed_jwt,
                      token_location = "header", secret = secret)
})
```

:warning: Please change the secret to a super secure secret of your choice. Please notice that you have to `preempt = c("sealr-jwt")` to routes that should **not** be protected.

#### Run the example

Copy the code from [below](#code_simple) in a new R file and 
save it under `jwt_simple_example.R`. In the R console, run:


```r
plumber::plumb("jwt_simple_example.R")
```

This will make the API available at `localhost:9090`.

In order to run this example, you need the following packages installed: 

- sealr
- plumber
- httr
- jose
- jsonlite


#### Get authentication

Using curl, Postman or a similar tool for sending HTTP requests, send a POST request with the details of one of the two users that are in the API's "database" (in this simplified example, a data frame).



| id|user             |password                                                     |
|--:|:----------------|:------------------------------------------------------------|
|  1|jane@example.com |$2a$12$Q1mj/W4gVWQBBoau.SLVo.3PTlGeG7ZtJvn336mZIHCyqUQCR2Bca |
|  2|bob@example.com  |$2a$12$jZqmt6U3dzXChKe92gYs1eGMQFmJw54In/1aLTsoQOurletQlqRJa |

For example, in curl: 

```
curl --data '{"user": "jane@example.com", "password": "12345"}' localhost:9090/authentication
```

gives back the JWT:

```
["eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTE0NDk5NTcsInVzZXJJRCI6MX0.0563N-dcz9zY-NF9DQpUnHIONZRWmZU1rb894xxHcNU"]
```

**Note**: You might get different JWTs as `jose::jwt_encode_hmac` automatically adds the time when the JWT was issued as a claim (`iat` claim). However, those examples should still work because we do not add an expiration time to the token -  something you should definetely consider for production use cases.  


Trying to authenticate with a user that is not in the database fails: 
```
curl --data '{"user": "drake@example.com", "password": "10111213"}' localhost:9090/authentication
```

```
{"status":["Failed."],"code":[401],"message":["User or password wrong."]}
```

#### Route without required authentication

Everyone can access the `/` route because it does not require authentication - the `sealr-jwt` filter is `preempt`ed for this route:
```
curl localhost:9090
["Access to route without authentication was successful."]
```

#### Route with authentication

Trying to access the `/secret` route without a JWT fails because it goes through the `sealr-jwt` filter where the `sealr::jwt` function will check for the correct authentication details - in this case a valid JWT in the Authorization header. 

```
curl localhost:9090/secret
```

```
{"status":["Failed."],"code":[401],"message":["Authentication required."]}
```

Use the JWT obtained with the first curl command to make an authenticated request to this route.

```
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTE0NDk5NTcsInVzZXJJRCI6MX0.0563N-dcz9zY-NF9DQpUnHIONZRWmZU1rb894xxHcNU" localhost:9090/secret
["Access to route requiring authentication was successful."]
```


#### Code {#code_simple}

```r
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
```


### Claims Example
In this example implementation (see full code [below](#code_claims)), we have two filters:

The filter `sealr-jwt` simply checks whether the user is authenticated and that the issuer claim `iss` is set to `mygreatplumberapi`, the value we set in the `authentication` route.
The second filter  `sealr-jwt-admin-only` additionally checks whether the user is an admin by validating that the claim `admin` is `TRUE`. 


```r
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
```


We now have two levels of access using filters: routes that are open to all authenticated users with a JWT issued by `mygreatplumberapi` and routes that are accessible to admins only. The former requires `preempt`ing the more restrictive `sealr-jwt-admin-only` filter. 

Unfortunately, it is currently not possible to extend this filter-based authorization mechanism to more than two authorization "levels" because `plumber` does not allow for preempting more than one filter per route. 
This problem is on the radar of the `plumber` team and they'll provide the opportunity to impose filters on specific
endpoints in the future (kind of "reverting" the `preempt` logic). See [this plumber issue](https://github.com/trestletech/plumber/issues/108).

As a workaround, you could put your authentication / authorization checks in the individual endpoints.
In this case, use `is_authed_*` functions instead of the `authenticate` wrapper.

#### Run the example
Copy the code from [below](#code_claims) in a new R file and 
save it under `jwt_claims_example.R`. In the R console, run:


```r
plumber::plumb("jwt_claims_example.R")
```

This will make the API available at `localhost:9090`.

In order to run this example, you need the following packages installed: 

- sealr
- plumber
- httr
- jose
- jsonlite

#### Get authentication

Using curl, Postman or a similar tool for sending HTTP requests, send a POST request with the details of one of the two users that are in the API's "database" (in this simplified example, a data frame).



| id|user             |password                                                     |admin |gender |
|--:|:----------------|:------------------------------------------------------------|:-----|:------|
|  1|jane@example.com |$2a$12$SWhVzWX1lz5DeFur9yrNZeOU7ttZruf1.Js0qIhKhaG0whQb6wO1K |TRUE  |woman  |
|  2|bob@example.com  |$2a$12$UyVFCVNrbwo6x5JeC5BluuY5sDM1QnFVkCbRdWoRqalxatksYwIIS |FALSE |man    |

Get the JWT for both users: 

- Jane 

```
curl --data '{"user": "jane@example.com", "password": "12345"}' localhost:9090/authentication
["eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NjE0NiwiYWRtaW4iOnRydWUsImdlbmRlciI6IndvbWFuIiwidXNlcklEIjoxfQ.AZqJFuXZkjwKbnULHfJVmBapFhZpBgLIUuX7HOJAUhU"]
```

- Bob 

```
curl --data '{"user": "bob@example.com", "password": "45678"}' localhost:9090/authentication
["eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NTgzNCwiYWRtaW4iOmZhbHNlLCJnZW5kZXIiOiJtYW4iLCJ1c2VySUQiOjJ9.WjRD5aIaqgApWJ-bf0VosbMZ3ovDyvRVvYug-5egL8s"]
```

**Note**: You might get different JWTs as we also add the time when the token was issued as a claim (`iat`). However, those examples should still work because we do not add an expiration time to the token -  something you should definetely consider for production use cases.  

#### Route with simple authentication

Both users can access the `/secret` route because they both have valid JWT issued by `mygreatplumberapi`. The route `preempt`s the more restrictive `sealr-jwt-admin-only` filter so even non-admin Bob has access.

- Jane
```
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NTc3NSwiYWRtaW4iOnRydWUsImdlbmRlciI6IndvbWFuIiwidXNlcklEIjoxfQ.FXLTGUcsn8yuiS7VqoGEjw94zQsmO6sYdWJeLeS-PhE" localhost:9090/secret

["Access to route that requires authentication was successful."]
```

- Bob
```
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NTgzNCwiYWRtaW4iOmZhbHNlLCJnZW5kZXIiOiJtYW4iLCJ1c2VySUQiOjJ9.WjRD5aIaqgApWJ-bf0VosbMZ3ovDyvRVvYug-5egL8s" localhost:9090/secret

["Access to route that requires authentication was successful."]
```

#### Route with admin-only authorization


In contrast, only Jane can access the `/secret-admin-only` route.

- Jane
```
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NTc3NSwiYWRtaW4iOnRydWUsImdlbmRlciI6IndvbWFuIiwidXNlcklEIjoxfQ.FXLTGUcsn8yuiS7VqoGEjw94zQsmO6sYdWJeLeS-PhE" localhost:9090/secret-admin-only

["Access to route that requires admin authorization was successful."]
```

- Bob 
```
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteWdyZWF0cGx1bWJlcmFwaSIsImlhdCI6MTU1MzY3NTgzNCwiYWRtaW4iOmZhbHNlLCJnZW5kZXIiOiJtYW4iLCJ1c2VySUQiOjJ9.WjRD5aIaqgApWJ-bf0VosbMZ3ovDyvRVvYug-5egL8s" localhost:9090/secret-admin-only

{"status":["Failed."],"code":[401],"message":["Authentication required."]}
```
#### Code {#code_claims}


```r
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
```

## Open ID Connect - Google

### Introduction 


The Google OAuth2 strategy allows you to use Google’s OpenID Connect
interface to authenticate and authorize your users. A detailed
introduction and best practices can be found
[here](https://developers.google.com/identity/protocols/OpenIDConnect).
The interface uses JWTs. Hence, the process can be considered stateless.
Addtionally, the user tokens can be used to access Google APIs.



### Example 
#### Obtain Google OAuth credentials 

In order to run this example, you need to obtain OAuth2.0 credentials for your plumber API 
so that Google later knows that it is authenticating the user to a legitimate application. 
For this, create a new **project** in the [Google API Console](https://console.developers.google.com/) - you 
may need to authorize your Google account first if you are not yet a user of Google's developer platform.

Once you have created your project, follow the instructions on "Obtain OAuth 2.0 credentials" [here](https://developers.google.com/identity/protocols/OpenIDConnect). When you have to select
the application type, select "Other". 
Store the client ID and the client secret as environment variables in your R session using 
the following commands. 



```r
Sys.setenv("GOOGLE_CLIENT_ID" = "yourid")
Sys.setenv("GOOGLE_CLIENT_SECRET" = "yoursecret")
```

This will make the client and secret available for your *current* R session. If you want
to make them available beyond your current session, use `usethis::edit_r_environ` and
add them in the file that opens like this: 

```
GOOGLE_CLIENT_ID="yourid"
GOOGLE_CLIENT_SECRET="yoursecret"
```
Save and close the file. 

#### Run the plumber API
Copy the code from [below](#code_google) in a new R file and 
save it under `oauth2_google_simple_example.R`. In the R console, run:


```r
plumber::plumb("oauth2_google_simple_example.R")
```

This will make the API available at `localhost:9090`.

In order to run this example, you need the following packages installed: 

- sealr
- plumber
- httr
- jose
- jsonlite


#### Authenticate yourself to the plumber API

Open your browser and enter `http://localhost:9090/authentication/` in the address bar.
You'll be redirected to Google. Authorize your application / plumber API. 
You'll be again redirected to a JSON response that, depending on your browser, should look something like this (tokens are blacked out):

![google return](/sealr/docs/images/google_oauth_return.png)

It contains:

- `access_token`: the token you would need if you wanted to access any of Google's APIs in your plumber API. If you only use Google to **authenticate** users, this will not be necessary.
- `expires_in`: how long the access token is valid in seconds. This value is set by Google. In this case, the access token is valid for one hour. 
- `refresh_token`: the token you can could to refresh your access token. We have not implemented the refresh logic in this example though. 
- `scope`: the scope your plumber API requested to authorize from the user. In this example, we only requested the "userinfo.profile" scope. 
- `token_type`: type of token. This will always be "Bearer". Prepend this to your HTTP Authorization Header (see below). 
- `id_token`: The ID token. A JSON Web Token (see section on JWT) that contains information about the identify of the user. This token is signed by Google. **This is the token you send in the HTTP Authorization header** (see below).

See also the explanation of the return values on [Google's OpenID Connect website](https://developers.google.com/identity/protocols/OpenIDConnect#authuser). 

#### Send an authenticated request

Open a terminal and enter the following command, replacing the YOUR_ID_TOKEN with 
the `id_token` from your response. 

```
curl -H "Authorization: Bearer YOUR_ID_TOKEN" localhost:9090/secret
```

The ID token will be quite long, so maybe first edit this command in your text editor of choice 
before copying it to the terminal. Hit enter. 

You should get back: 

````
{"message":["Successfully accessed the secret endpoint."]}
````



#### Code {#code_google}


```r
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
```



