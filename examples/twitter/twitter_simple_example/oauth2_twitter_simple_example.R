# define contant variables
TWITTER_CONSUMER_KEY <- Sys.getenv("TWITTER_CONSUMER_KEY")
TWITTER_CONSUMER_SECRET <- Sys.getenv("TWITTER_CONSUMER_SECRET")

# get the discovery document with the required URLs
response <- httr::GET("https://accounts.google.com/.well-known/openid-configuration")
discovery_document <- jsonlite::fromJSON(httr::content(response, type = "text", encoding = "UTF-8"))

# define a new plumber router
pr <- plumber::plumber$new()

# integrate the jwt strategy in a filter
pr$filter("sealr-oauth2-twitter", function (req, res) {
  # simply call the strategy and forward the request and response
  # check whether token is valid?!
})

# define authentication route to issue web tokens (exclude "sealr-jwt" filter using preempt)
pr$handle("GET", "/authentication", function (req, res) {
  token <- rtweet::create_token(app = "sealrtest", TWITTER_CONSUMER_KEY, TWITTER_CONSUMER_SECRET, set_renv = FALSE)
  # TODO: parse info from environment and return to user
  return(list(oauth_token = token$credentials$oauth_token,
              oauth_token_secret = token$credentials$oauth_token_secret))
}, preempt = c("sealr-oauth2-twitter"), serializer = plumber::serializer_unboxed_json())

# protected path
pr$handle("GET", "/", function (req, res) {
  list(message = "SUCCESS")
})

# start API server
pr$run(host="0.0.0.0", port=9090)

