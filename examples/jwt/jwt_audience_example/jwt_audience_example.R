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
  sealr::jwt(req = req, res = res, secret = secret)
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
pr$run(host = "0.0.0.0", port = 9090)
