#' JWT Strategy
#'
#' This function implements a JWT authentication strategy. The function can be used as a filter in front
#' of the routes. The strategy uses extracts the token from the HTTP Authorization header with the scheme 'bearer'.
#'
#' @param req Request object.
#' @param res Response object.
#' @param client_id character.
#' @param hd character.
#'
#' @importFrom stringr str_remove str_trim
#' @importFrom jose jwt_split
#' @importFrom plumber forward
#' @importFrom anytime anytime
#' @importFrom httr GET content
#' @importFrom jsonlite fromJSON
#'
#' @examples
#' \dontrun{
#' pr$filter("sealr-jwt", function (req, res) {
#'   sealr::jwt(req = req, res = res, secret = secret)
#' })
#' }
#'
#' @export
#'

oauth2_google <- function (req,
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

  ## parse token -----------------------------------------------------------------------------------------

  # trim authorization token
  req$HTTP_AUTHORIZATION <- stringr::str_remove(req$HTTP_AUTHORIZATION, "Bearer\\s")
  req$HTTP_AUTHORIZATION <- stringr::str_trim(req$HTTP_AUTHORIZATION)

  # parse google's jwt
  jwt <- jose::jwt_split(req$HTTP_AUTHORIZATION)

  # add token to request
  req$jwt <- jwt$payload

  ## check signature -------------------------------------------------------------------------------------

  # download public key file
  key_file <- httr::GET(jwks_uri)
  parsed_key_file <- jsonlite::fromJSON(httr::content(key_file, type = "text"))$keys

  # parse public key
  pub_key <- jose::jwk_read(parsed_key_file[2, ])

  # check signature
  jose::jwt_decode_sig(req$HTTP_AUTHORIZATION, pub_key)

  ## check jwt payload------------------------------------------------------------------------------------

  # check if iis is correct
  if (!stringr::str_detect(jwt$payload$iss, "https://accounts.google.com||accounts.google.com")) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # check if client id matches
  if (jwt$payload$aud != client_id) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # check if token expired
  if (as.numeric(as.POSIXct(Sys.time())) > jwt$payload$exp) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # check if hd is valid
  if (!is.null(hd)) {
    if (jwt$payload$hd != hd) {
      res$status <- 401
      return(list(status="Failed.",
                  code=401,
                  message="Authentication required."))
    }
  }

  # redirect to routes
  plumber::forward()
}
