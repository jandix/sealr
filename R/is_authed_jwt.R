#' JWT Strategy
#'
#' @description  \code{is_authed_jwt} checks whether a JWT passed as part of the HTTP request is valid.
#' The function can be passed to \code{\link{authenticate}}'s \code{is_authed_fun}
#' argument or it can be used standalone in any plumber endpoint.
#' \code{is_authed_jwt} extracts the token from the HTTP Authorization header with the scheme 'bearer'.
#'
#' @param req Request object.
#' @param res Response object.
#' @param secret character. The secret that was used to sign your JWT. The secret is converted
#' to raw bytes in the function. Default NULL.
#' @param token_location character. Location of JWT. Either "header" or "cookie".
#' See \code{\link{get_token_from_req}} for details.
#' @param pubkey character. Public RSA or ECDSA key that was used to generate the JWT. Default NULL.
#' @param claims named list. Claims that should be checked in the JWT. Default NULL.
#' @return list with the following elements:
#' \itemize{
#'   \item is_authed: TRUE or FALSE. Result of the check whether the JWT is valid.
#'   \item status: character. Optional. Short description of HTTP status code.
#'   \item code: integer. Optional. HTTP status code.
#'   \item message: character. Optional. Longer description.
#' }
#' @examples
#' \dontrun{
#'  pr$filter("sealr-jwt-filter", function(req, res){ # usage in a filter
#'    sealr::authenticate(req = req, res = res, sealr::is_authed_jwt, secret = "averylongsupersecretsecret")
#'  })
#' }
#'
#
#' \dontrun{
#'  pr$handle("GET", "/somedata", function(req, res){ # usage in an endpoint
#'    is_authed_list <- sealr::is_authed_jwt(req, res, secret = "averylongsupersecretsecret",
#'                                      claims = list(iss = "myplumberapi"))
#'    if (is_authed_list$is_authed){
#'      return("somedata")
#'    } else {
#'      # return error or do something else
#'      is_authed_list$is_authed <- NULL
#'      return(is_authed_list)
#'    }
#'  })
#' }
#' @importFrom stringr str_remove str_trim
#' @importFrom jose jwt_decode_hmac jwt_decode_sig
#' @export


is_authed_jwt <- function (req, res, token_location, secret = NULL,  pubkey = NULL, claims = NULL) {

  # ensure that the user passed the request object
  if (missing(req))
    stop("Please pass the request object.")

  # ensure that the user passed the response object
  if (missing(res) == TRUE)
    stop("Please pass the response object.")

  if (missing(token_location))
    stop("Please specify a token location.")

  # ensure that the user passed a secret
  if (is.null(secret) && is.null(pubkey))
    stop("Please define either a secret or a public key.")

  if (!is.null(secret) && !is.null(pubkey))
    stop("Please define either a secret or a public key, not both.")

  if (!is.null(secret)){
    if (nchar(secret) < 1)
      stop("Your secret is empty. This is a possible security risk.")
    # convert secret to bytes
    secret <- charToRaw(secret)
  }

  # check if request includes authorization header or session cookie
  token <- get_token_from_req(req, token_location)

  # remove "Bearer" part from token
  token <- clean_bearer_token(token)

  # decode the token and check whether it is valid
  if (!is.null(pubkey)){
    # public key is specified -> RSA or EDSCA was used
    payload <- tryCatch(jose::jwt_decode_sig(token, pubkey = pubkey),
                      error = function (e) NULL)
  } else {
    # secret is specified -> HMAC was used
    payload <- tryCatch(jose::jwt_decode_hmac(token, secret = secret),
                      error = function (e) NULL)
  }

  # return FALSE if token could not be decoded, if it is expired or if checked claims are not valid
  if (is.null(payload) || is_jwt_expired(payload) || !check_all_claims(payload, claims)) {
    return(is_authed_return_list_401())
  }

  return(is_authed_return_list(TRUE))
}
