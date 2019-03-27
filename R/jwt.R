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
#' @param pubkey character. Public RSA or ECDSA key that was used to generate the JWT. Default NULL.
#' @param claims named list. Claims that should be checked in the JWT. Default NULL.
#' @return list with the following elements:
#' \itemize{
#'   \item is_authed: TRUE or FALSE. Result of the check whether the JWT is valid.
#'   \item status: character. Optional. Short description of HTTP status code.
#'   \item code: integer. Optional. HTTP status code.
#'   \item message: character. Optional. Longer description.
#' }
#'
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


is_authed_jwt <- function (req, res, secret = NULL,  pubkey = NULL, claims = NULL) {

  # ensure that the user passed the request object
  if (missing(req))
    stop("Please pass the request object.")

  # ensure that the user passed the response object
  if (missing(res) == TRUE)
    stop("Please pass the response object.")

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

  # check if request includes authorization header
  if (is.null(req$HTTP_AUTHORIZATION)) {
    return(is_authed_return_list_401())
  }

  # trim authorization token
  req$HTTP_AUTHORIZATION <- stringr::str_remove(req$HTTP_AUTHORIZATION, "Bearer\\s")
  req$HTTP_AUTHORIZATION <- stringr::str_trim(req$HTTP_AUTHORIZATION)

  # decode the token and check whether it is valid
  if (!is.null(pubkey)){
    # public key is specified -> RSA or EDSCA was used
    payload <- tryCatch(jose::jwt_decode_sig(req$HTTP_AUTHORIZATION, pubkey = pubkey),
                      error = function (e) NULL)
  } else {
    # secret is specified -> HMAC was used
    payload <- tryCatch(jose::jwt_decode_hmac(req$HTTP_AUTHORIZATION, secret = secret),
                      error = function (e) NULL)
  }

  # return FALSE if token could not be decoded, if it is expired or if checked claims are not valid
  if (is.null(payload) || is_jwt_expired(payload) || !check_all_claims(payload, claims)) {
    return(is_authed_return_list_401())
  }

  return(is_authed_return_list(TRUE))
}


#'
#' This function checks that all claims passed in the \code{claims} argument of
#' the \code{\link{is_authed_jwt}} function are correct.
#' @param payload JWT payload extracted with jose::jwt_decode_hmac.
#' @param claims named list of claims to check in the JWT. Claims can be nested.
#' @return TRUE if the all claims are present in the JWT, FALSE if not.
#' @importFrom purrr map2_lgl
#' @export

check_all_claims <- function(payload, claims){

  claim_values <- claims
  claim_names <- names(claims)

  results <- purrr::map2_lgl(claim_names, claim_values, check_claim, payload = payload)
  return(all(results))
}


#'
#' This function checks that a claim passed to the \code{\link{is_authed_jwt}} function is valid in the
#' given JWT.
#' A claim consists of a claim name (e.g. "iss") and a claim value (e.g. "company A").
#' Claim values can also be named lists themselves.
#' The function recursively extracts the value for claim_name from the payload.
#' If the claim_value is atomic, it compares
#' the retrieved value with the claimed value. Otherwise, it applies check_claim
#' to claim_value recursively.
#' @param claim_name name of the claim in the JWT, e.g. "iss".
#' @param claim_value value the claim should have to pass the test.
#' @param payload JWT payload extracted with jose::jwt_decode_hmac.
#' @return TRUE if the claim is present in the JWT, FALSE if not.
#' @importFrom purrr vec_depth map2_lgl
#' @export

check_claim <- function(claim_name, claim_value, payload){

  # recursion at end, claim_value is just atomic (e.g. "Alice")
  if(purrr::vec_depth(claim_value) == 1){

    payload_claim_value <- payload[[claim_name]]
    # claim does not exist in payload
    if (is.null(payload_claim_value)) {
      return(FALSE)
    }

    # compare payload value with expected value
    return(identical(payload_claim_value, claim_value))

  } else {
    # claim_value is a list --> recurse
    # cannot subset payload because claim_name does not exist in payload
    # -> wrong claim_value
    if (!claim_name %in% names(payload)){
      return(FALSE)
    }
    # recursively apply to all elements of claim_value
    return(all(c(purrr::map2_lgl(names(claim_value), claim_value, check_claim,
                                 payload = payload[[claim_name]]))))
  }
}

#' This function checks whether a JWT is expired.
#' @param payload  list. Payload of JWT.
#' @return TRUE if JWT is expired, FALSE if not
#' (either current time < expiration time or no exp claim in JWT).
is_jwt_expired <- function(payload){
  if (! "exp" %in% names(payload)){
    # no exp claim there
    return(FALSE)
  }

  return(as.numeric(Sys.time()) > payload$exp)
}
