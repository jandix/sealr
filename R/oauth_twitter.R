#' JWT Strategy
#'
#' This function implements a Twitter user authentication strategy. The function can be used as a filter in front
#' of the routes. The strategy uses extracts the token from the HTTP Authorization header with the scheme 'bearer'.
#'
#' @param req Request object.
#' @param res Response object.
#' @param client_id character.
#' @param hd character.
#' @param jwks_uri character.
#'
#' @importFrom stringr str_remove str_trim
#' @importFrom jose jwt_decode_sig
#' @importFrom anytime anytime
#' @importFrom httr GET content
#' @importFrom jsonlite fromJSON
#' @importFrom plumber forward
#'
#' @examples
#' \dontrun{
#' pr$filter("sealr-jwt", function (req, res) {
#'   sealr::oauth2_google(req = req, res = res, secret = secret)
#' })
#' }
#'
#' @export
#'

oauth1a_twitter <- function (req,
                           res,
                           client_id,
                           hd = NULL,
                           jwks_uri = "https://www.googleapis.com/oauth2/v3/certs") {

  ## check missing parameters ----------------------------------------------------------------------------

  # ensure that the user passed the request object
  if (missing(req) == TRUE)
    stop("Please pass the request object.")

  # ensure that the user passed the response object
  if (missing(res) == TRUE)
    stop("Please pass the response object.")

  # ensure that the user passed the client_id
  if (missing(client_id) == TRUE)
    stop("Please pass the Google client id.")

  # ensure that the request includes HTTP_AUTHORIZATION header
  if (!("HTTP_AUTHORIZATION" %in% names(req))) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  ## parse token -----------------------------------------------------------------------------------------

  # trim authorization token
  req$HTTP_AUTHORIZATION <- stringr::str_remove(req$HTTP_AUTHORIZATION, "Bearer\\s")
  req$HTTP_AUTHORIZATION <- stringr::str_trim(req$HTTP_AUTHORIZATION)

  # parse google's jwt
  jwt <- tryCatch(jwt_split(req$HTTP_AUTHORIZATION),
                  error = function (e) NULL)

  # if jwt not valid send error
  if (is.null(jwt)) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  ## check signature -------------------------------------------------------------------------------------

  # ensure that the jwt header includes kid
  if (!("kid" %in% names(jwt$header$kid))) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # download public key file
  response <- httr::GET(jwks_uri)
  if (httr::http_error(response)) {
    res$status <- 500
    return(list(status="Failed.",
                code=500,
                message="Authentication Error. Hint: jwks_uri"))
  }
  jwks <- jsonlite::fromJSON(httr::content(response, type = "text", encoding = "UTF-8"))$keys

  # match kid
  index <- FALSE
  for (i in 1:nrow(jwks)) {
    if (jwks$kid[i] == jwt$header$kid) {
      index <- i
      break
    }
  }

  if (!index) {
    res$status <- 500
    return(list(status="Failed.",
                code=500,
                message="Authentication Error. Hint: jwks_uri"))
  }

  # parse public key
  pub_key <- jose::jwk_read(jwks[index, ])

  # check signature
  payload <- tryCatch(jose::jwt_decode_sig(req$HTTP_AUTHORIZATION, pub_key),
                      error = function (e) NULL)

  # if token not valid send error
  if (is.null(payload)) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # append jwt payload to request
  req$jwt_payload <- payload

  ## check jwt payload------------------------------------------------------------------------------------

  # check if iis is correct
  if (!stringr::str_detect(payload$iss, "https://accounts.google.com||accounts.google.com")) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # check if client id matches
  if (payload$aud != client_id) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # check if token expired
  if (as.numeric(as.POSIXct(Sys.time())) > payload$exp) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # check if hd is valid
  if (!is.null(hd)) {
    if (payload$hd != hd) {
      res$status <- 401
      return(list(status="Failed.",
                  code=401,
                  message="Authentication required."))
    }
  }

  # redirect to routes
  plumber::forward()
}


twitter_create_oauth_list <- function(oauth_consumer_key,
                                      oauth_nonce, oauth_token = NULL){

  oauth_signature_method <- "HMAC-SHA1"
  oauth_version <- "1.0"
  oauth_timestamp <- as.character(as.integer(Sys.time()))

  list(oauth_consumer_key = oauth_consumer_key,
       oauth_nonce = oauth_nonce,
       oauth_signature_method =  oauth_signature_method,
       oauth_timestamp = oauth_timestamp,
       oauth_version = oauth_version)
}



twitter_build_header_string <- function(request_url, http_method, oauth_consumer_secret,
                                        twitter_oauth_list, params_list = NULL){

  oauth_signature <- twitter_create_signature(request_url, http_method, oauth_consumer_secret,
                                              twitter_oauth_list, params_list)

  twitter_oauth_list$oauth_signature <- oauth_signature
  header_list <- c(twitter_oauth_list, params_list)

  kv_pairs <- map2_chr(names(header_list), header_list,
                       function(x, y) paste0(URLencode(x, reserved = TRUE), "=", "\"",
                                             URLencode(y, reserved = TRUE), "\""))
  kv_pairs_comma_sep <- paste(kv_pairs, collapse = ", ")
  paste0("OAuth ", kv_pairs_comma_sep)
}

twitter_create_signature <- function(request_url, http_method, oauth_consumer_secret,
                                     twitter_oauth_list, params_list = NULL){
  # create signature
  # https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature.html
  to_be_signed <- c(params_list, twitter_oauth_list)
  names_encoded <- purrr::map_chr(names(to_be_signed), function(x) URLencode(x, reserved = TRUE))
  encoded <- purrr::map_chr(to_be_signed, function(x) URLencode(x, reserved = TRUE))

  # set names and sort
  names(encoded) <- names_encoded
  encoded <- encoded[order(names(encoded))]

  # paste keys and values together with = and &
  parameter_string_values <- purrr::map2_chr(names(encoded), encoded,
                                             function(x, y) paste0(x, "=", y))
  parameter_string <- paste(parameter_string_values, collapse = "&")

  # create signature base string
  sig_base_string <- paste(
    toupper(http_method),
    URLencode(request_url, reserved = TRUE),
    URLencode(parameter_string, reserved = TRUE),
    sep = "&"
  )
  # generate signing key
  sig_key <- paste0(URLencode(oauth_consumer_secret, reserved = TRUE), "&")
  sig <- httr::hmac_sha1(sig_key, sig_base_string)
  print(sig)
  URLencode(httr::hmac_sha1(sig_key, sig_base_string), reserved = TRUE)
}


twitter_oauth_list <- twitter_create_oauth_list(Sys.getenv("TWITTER_CONSUMER_KEY"), oauth_nonce = stringi::stri_rand_strings(1, 30))
twitter_oauth_list


header_string <- twitter_build_header_string("https://api.twitter.com/oauth/request_token",
                            "POST",
                            Sys.getenv("TWITTER_CONSUMER_SECRET"),
                            twitter_oauth_list = twitter_oauth_list,
                            params_list = list(oauth_callback = "http://localhost:9090/authentication/redirect"))
header_string
