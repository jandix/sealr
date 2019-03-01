# create new plumber router
pr <- plumber::plumber$new()

# define secret
secret <- charToRaw("3ec9aaf4a744f833e98c954365892583")

# define jwt filter
pr$filter("sealr-google-oauth2", function (req, res) {
  # try if access token is still working

  # try to refresh token using refresh token


  if (is.null(req$HTTP_AUTHORIZATION)) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }
  req$HTTP_AUTHORIZATION <- stringr::str_remove(req$HTTP_AUTHORIZATION, "Bearer\\s")
  auth <- tryCatch(jose::jwt_decode_hmac(req$HTTP_AUTHORIZATION, secret = secret),
                   error = function (e) NULL)
  if (is.null(auth)) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }
  plumber::forward()
})

# define test route without auth
pr$handle("GET", "/", function (req, res) {
  return(list(message = "Welcome."))
}, preempt = c("passport-jwt"))

# define auth route
pr$handle("POST", "/authentication", function (req, user = NULL, password = NULL) {
  if (is.null(user) || is.null(password)) {
    return(list(status="Failed.",
                code=404,
                message="Please return password or username."))
  }
  # define jwt payload
  payload <- jose::jwt_claim(userID = "192831")
  jwt <- jose::jwt_encode_hmac(payload, secret = secret)
  return(jwt = jwt)
}, preempt = c("passport-jwt"))

# define test route with auth
pr$handle("GET", "/secret", function (req, res) {
  return(list(message = "Welcome to the secret path."))
})

pr$run(host="0.0.0.0", port=9090)
