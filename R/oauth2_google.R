#' JWT Strategy
#'
#' This function implements a JWT authentication strategy. The function can be used as a filter in front
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

is_authed_oauth2_google <- function (req,
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
    return(FALSE)
  }

  ## parse token -----------------------------------------------------------------------------------------

  # trim authorization token
  req$HTTP_AUTHORIZATION <- stringr::str_remove(req$HTTP_AUTHORIZATION, "Bearer\\s")
  req$HTTP_AUTHORIZATION <- stringr::str_trim(req$HTTP_AUTHORIZATION)

  # parse google's jwt
  jwt <- tryCatch(jwt_split(req$HTTP_AUTHORIZATION),
                  error = function (e) NULL)

  # if jwt not valid send error
  if (is.null(jwt)) return(FALSE)

  ## check signature -------------------------------------------------------------------------------------

  # ensure that the jwt header includes kid
  if (!("kid" %in% names(jwt$header$kid))) return(FALSE)

  # download public key file
  response <- httr::GET(jwks_uri)
  if (httr::http_error(response)) return(FALSE)

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
  if (is.null(payload)) return(FALSE)

  # append jwt payload to request
  req$jwt_payload <- payload

  ## check jwt payload------------------------------------------------------------------------------------

  # check if iss is correct
  if (!stringr::str_detect(payload$iss, "https://accounts.google.com||accounts.google.com")) {
    return(FALSE)
  }

  # check if client id matches
  if (payload$aud != client_id) return(FALSE)

  # check if token expired
  if (is_jwt_expired(payload)) return(FALSE)

  # check if hd is valid
  if (!is.null(hd)) {
    if (payload$hd != hd) return(FALSE)
  }

  return(TRUE)
}
