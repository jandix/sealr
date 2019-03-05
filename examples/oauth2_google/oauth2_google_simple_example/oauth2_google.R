# define contant variables
CLIENT_ID <- Sys.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET <- Sys.getenv("GOOGLE_CLIENT_SECRET")

# get the discovery document with the required URLs
response <- httr::GET("https://accounts.google.com/.well-known/openid-configuration")
discovery_document <- jsonlite::fromJSON(httr::content(response, type = "text", encoding = "UTF-8"))

# define a new plumber router
pr <- plumber::plumber$new()

# integrate the jwt strategy in a filter
pr$filter("sealr-oauth2-google", function (req, res) {
  # simply call the strategy and forward the request and response
  sealr::oauth2_google(req = req, res = res, client_id = CLIENT_ID)
})

# define authentication route to issue web tokens (exclude "sealr-jwt" filter using preempt)
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

# define authentication route to issue web tokens (exclude "sealr-jwt" filter using preempt)
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
pr$handle("GET", "/", function (req, res) {
  list(message = "SUCCESS")
})

# start API server
pr$run(host="0.0.0.0", port=9090)
