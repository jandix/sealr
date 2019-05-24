# define contant variables
# this follows more or less the steps outlined here:
# https://developers.google.com/identity/protocols/OpenIDConnect#authenticatingtheuser

CLIENT_ID <- Sys.getenv("GOOGLE_CLIENT_ID") # id of your app
CLIENT_SECRET <- Sys.getenv("GOOGLE_CLIENT_SECRET") # client secret of the application

# get the discovery document with the required URLs for step 4
response <- httr::GET("https://accounts.google.com/.well-known/openid-configuration")
discovery_document <- jsonlite::fromJSON(httr::content(response, type = "text", encoding = "UTF-8"))

# define a new plumber router
pr <- plumber::plumber$new()
# register encrypted cookie for csrf token
# put key in environment variable for production
pr$registerHooks(plumber::sessionCookie(key = "EPCGoaMO9dIxIEPoOjOL4sjL4U6w0GQ5", name = "state"))

# integrate the google strategy in a filter
pr$filter("sealr-oauth2-google", function (req, res) {
  # simply call the strategy and forward the request and response
  sealr::authenticate(req = req, res = res, token_location = "header",
                      is_authed_fun = sealr::is_authed_oauth2_google, client_id = CLIENT_ID)
})

# define authentication route to issue web tokens (exclude "sealr-google" filter using preempt)
pr$handle("GET", "/authentication", function (req, res) {
  # get authorization endpoint
  url <- discovery_document$authorization_endpoint

  # STEP 1: create CSRF token
  state <- as.character(openssl::sha1(openssl::rand_bytes(n = 30)))
  class(state) <- "character" # necessary because state is hash / sha1 class which has no json serialization
  req$session$state <- state # set as encrypted cookie in session

  # STEP 2: Send an authentication request to Google
  query <- list(client_id = CLIENT_ID,
                redirect_uri = "http://localhost:9090/authentication/redirect",
                scope = "https://www.googleapis.com/auth/userinfo.profile",
                state = state,
                response_type = "code")
  auth_url <- httr::parse_url(url = url)
  auth_url$query <- query
  auth_url <- httr::build_url(auth_url)
  res$status <- 301
  res$setHeader("Location", auth_url)
  return()
}, preempt = c("sealr-oidc-google"))

# define authentication route to issue web tokens (exclude "sealr-oidc-google" filter using preempt)
pr$handle("GET", "/authentication/redirect", function (req, res, state = NULL, code = NULL, error = NULL) {

  # STEP 3: Confirm anti-forgery state token
  if(req$session$state != state){
    return(sealr::is_authed_return_list_401())
  }

  # STEP 4: Exchange code for access token and ID token
  token_url <- discovery_document$token_endpoint
  body <- list(
    code = code,
    client_id = CLIENT_ID,
    client_secret = CLIENT_SECRET,
    redirect_uri = "http://localhost:9090/authentication/redirect",
    grant_type = "authorization_code"
  )
  response <- httr::POST(token_url, body = body)
  parsed_response <- jsonlite::fromJSON(httr::content(response, type = "text",
                                                      encoding = "UTF-8"))

  return(parsed_response)
}, preempt = c("sealr-oidc-google"))

# protected path
pr$handle("GET", "/secret", function (req, res) {
  list(message = "Successfully accessed the secret endpoint.")
})

# start API server
pr$run(host = "0.0.0.0", port = 9090, swagger = FALSE)
