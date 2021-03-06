
# Exchanging and storing tokens

The token you provide to the user needs to be stored on their machine so that 
they can later send it back in the request to your plumber API. Where and how 
the token is stored depends on your use case and what the service making the requests to your API looks like.

## Exchanging tokens

### Issueing the token 

When you first issue a token to the user - i.e. in the `authentication` endpoint of our examples - , you have two options how you want to return it to them: send it as part of the HTTP response or set a token in the browser of the user. 

#### Return in HTTP response

Return the token in the HTTP response by including the appropriate `return` statement at the end of your `authentication` endpoint. 


```r
pr$handle("POST", "/authentication", function (req, res, user = NULL, password = NULL) {

  # ... 
  # CODE HERE
  # ...
  
  # return jwt as response
  return(jwt = jwt)
}, preempt = c("sealr-jwt"))
```

This is the most flexible way as it allows the user to handle the token according to their needs. They could...

- ... store the token somewhere and later include it in an R script or R Markdown. For example, if the user wants to generate reports and needs to use your API in order to do this. They should take care to follow [guidelines](https://db.rstudio.com/best-practices/managing-credentials/) on how to securely manage credentials and never include the token in their scripts.
- ... store the token in their web browser's local storage. The local storage of a web browser is.  This is relevant if the user makes the request from a web application from their browser (see . The implementation of the storing mechanism would be part of the frontend code. All frontend oriented languages support storing 

### Cookie

### HTTP Authorization header 

### Interactive R session 
If your users simply use the token to make requests from an R script, e.g. by executing an `.R` file or generating 
an R markdown file, they should store their token in a secure way. 

Some resources to get started: 
- [https://db.rstudio.com/best-practices/managing-credentials/](https://db.rstudio.com/best-practices/managing-credentials/)

### Another application 
Another service 

### Web application 

Finally, you could have a "typical" web frontend-backend infrastructure where you 
want to use plumber to serve data to a frontend that your user can visit in their 
Internet browser. 

Typically, in web development, there are two approaches to storing user data. 


## Local Storage 

## Cookie

Instead of requiring the user to send the JWT back in the HTTP Authorization header, 
you can also use a cookie in the browser of the API user to store the 
JWT. This way, the user does not have to remember to send the JWT in the 
Authorization header. 





Instead of requiring the user to send the JWT back in the HTTP Authorization header, 
you can also use a cookie in the browser of the API user to store the 
JWT. This way, the user does not have to remember to send the JWT in the 
Authorization header. 

### Cookie example
In this example, we use an encrypted cookie to store the JWT. You can find the 
full code for this example at the [end of this page](#code). 
In order to do this, we register an encrypted session cookie ([see plumber docs](https://www.rplumber.io/docs/rendering-and-output.html#encrypted-cookies)):


```r
# define a new plumber router
pr <- plumber::plumber$new()
# register cookie
pr$registerHooks(plumber::sessionCookie(key = "EPCGoaMO9dIxIEPoOjOL4sjL4U6w0GQ5", name = "token"))
```

In the `authentication` route, we then can set the JWT in the cookie.
Note that we do not return the JWT to the user because the JWT will be transferred in the cookie instead.


```r
pr$handle("POST", "/authentication", function (req, res, user = NULL, password = NULL) {
  # ...
  # ...
  # set cookie
  req$session$token <- jwt
  return()
})
```

The filter looks the same as in the simple example except that we have to change the `token_location` parameter to `"cookie"` instead of `"header"`. 


```r
# integrate the jwt strategy in a filter
pr$filter("sealr-jwt", function (req, res) {
  # simply call the strategy and forward the request and response
  # please change the secret
  sealr::authenticate(req = req, res = res, is_authed_fun = sealr::is_authed_jwt,
                      token_location = "cookie", secret = secret)
})
```

:warning: Please change the secret to a super secure secret of your choice. Please notice that you have to `preempt = c("sealr-jwt")` to routes that should **not** be protected.

**Run the example**

Copy the code from [below](#code) in a new R file and 
save it under `jwt_cookie_example.R`. In the R console, run:


```r
plumber::plumb("jwt_cookie_example.R")
```

In order to run this example, you need the following packages installed: 

- sealr
- plumber
- httr
- jose
- jsonlite


**Get authentication**

Using curl, Postman or a similar tool for sending HTTP requests, send a POST request with the details of one of the two users that are in the API's "database" (in this simplified example, a data frame).



| id|user             |password                                                     |
|--:|:----------------|:------------------------------------------------------------|
|  1|jane@example.com |$2a$12$zpd7xktqLvW0sDknZ9O4ReSeT0VA6kSMfa.3UlUpMTenfrsURMF7q |
|  2|bob@example.com  |$2a$12$/9D7BQMokkW9bXUgsKl/wueF8jDfxo2Zd6d.2RZ/6ybmohPom6w4q |

For example, in curl: 

**Note**: You might get different encrypted JWTs in your `cookies_jane.txt` as `jose::jwt_encode_hmac` automatically adds the time when the JWT was issued as a claim (`iat` claim). 

```
curl  --cookie-jar cookies_jane.txt --data '{"user": "jane@example.com", "password": "12345"}' localhost:9090/authentication
```

The `--cookie-jar` argument will store the cookie in a plain-text file in your current directory called `cookies_jane.txt`.

If you inspect this file (e.g. using `cat cookies_jane.txt`), you should see something like this: 

```
# Netscape HTTP Cookie File
# https://curl.haxx.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.

localhost	FALSE	/	FALSE	0	token	R/cOKStnaCrwojcbL4Uk1602scv7ln9PClDYO2LlfHd0zYtd+vYrGB6oTX7wvpp5hmipFxqnQ0FDwEdz1H7IjCr6KCxxUHnpWu8r0IjCA4zLHbJz/i5npGe16Ei+OhbOGbluT/An+0GnfzXsna4q4vHoB2P+GkUPZL3Xe7tZxIX+UHSk005tX89NcSLpVy6J
```

The token is the gibberish part at the end. It is indeed the JWT but it is encrypted and hence does not *look* like a JWT. 

Trying to get a token cookie for a user that is not in the database of course fails: 

```
curl --cookie-jar cookies_drake.txt --data '{"user": "drake@example.com", "password": "10111213"}' localhost:9090/authentication
```

```
{"status":["Failed."],"code":[401],"message":["User or password wrong."]}
```

**Route without required authentication**

Everyone can access the `/` route because it does not require authentication - the `sealr-jwt` filter is `preempt`ed for this route:
```
curl localhost:9090
["Access to route without authentication was successful."]
```

**Route with required authentication**

Trying to access the `/secret` route without a valid cookie fails because it goes through the `sealr-jwt` filter where the `sealr::jwt` function will check for the correct authentication details - in this case a valid JWT in `token` cookie. 

```
curl localhost:9090/secret
```

```
{"status":["Failed."],"code":[401],"message":["Authentication required."]}
```

But if you add the cookies for Jane to the request, authentication is successful.

```
curl --cookie cookies_jane.txt localhost:9090/secret
```

```
["Access to route requiring authentication was successful."]
```


**Code** {code}

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
```
