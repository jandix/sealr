#' JWT Strategy
#'
#' This function implements a JWT authentication strategy. The function can be used as a filter in front
#' of the routes. The strategy uses extracts the token from the HTTP Authorization header with the scheme 'bearer'.
#'
#' @param req Request object.
#' @param res Response object.
#' @param secret character. This should be the secret that use to sign your JWT. The secret is converted
#' to raw bytes in the function. Default NULL. Either specify pubkey or secret.
#' @param pubkey public key. Default NULL. Either specify pubkey or secret.
#' @param claims named list. Claims that should be checked in the JWT. Default NULL.
#' @importFrom stringr str_remove str_trim
#' @importFrom jose jwt_decode_hmac jwt_decode_sig
#' @importFrom plumber forward
#'
#' @examples
#' \dontrun{
#' pr$filter("sealr-jwt", function (req, res) {
#'   sealr::jwt(req = req, res = res, secret = secret, claims = list(iss = "company A"))
#' })
#' }
#'
#' @export
#'

jwt <- function (req, res, secret = NULL,  pubkey = NULL, claims = NULL) {

  # ensure that the user passed the request object
  if (missing(req))
    stop("Please pass the request object.")

  # ensure that the user passed a secret
  if (is.null(secret) && is.null(pubkey))
    stop("Please define either a secret or a public key.")

  if (!is.null(secret) && !is.null(pubkey))
    stop("Please define either a secret or a public key, not both.")

  if (!is.null(secret)){
    if (nchar(secret) < 1)
      warning("Your secret is empty. This is a possible security risk.")
    # convert secret to bytes
    secret <- charToRaw(secret)
  }

  # check if request includes authorization header
  if (is.null(req$HTTP_AUTHORIZATION)) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # trim authorization token
  req$HTTP_AUTHORIZATION <- stringr::str_remove(req$HTTP_AUTHORIZATION, "Bearer\\s")
  req$HTTP_AUTHORIZATION <- stringr::str_trim(req$HTTP_AUTHORIZATION)

  # check if token is valid
  if (!is.null(pubkey)){
    # public key is specified
    token <- tryCatch(jose::jwt_decode_sig(req$HTTP_AUTHORIZATION, pubkey = pubkey),
                      error = function (e) NULL)
  } else {
    # secret case
    token <- tryCatch(jose::jwt_decode_hmac(req$HTTP_AUTHORIZATION, secret = secret),
                      error = function (e) NULL)
  }

  # if token not valid send error
  if (is.null(token)) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # check that claims are correct
  if (!check_all_claims(token, claims)){
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # redirect to routes
  plumber::forward()
}


#'
#' This function checks that all claims passed by \code{...} to the jwt function
#' are correct.
#' @param token JWT extracted with jose::jwt_decode_hmac.
#' @param claims named list of claims to check in the JWT
#' @return TRUE if the all claims are present in the JWT, FALSE if not.
#' @importFrom purrr map2_lgl
#' @export

check_all_claims <- function(token, claims){

  claim_values <- claims
  claim_names <- names(claims)
  if ("" %in% claim_names){
    return(FALSE)
  }

  results <- purrr::map2_lgl(claim_names, claim_values, check_claim, token = token)
  return(all(results))
}


#'
#' This function checks that a claim passed to the jwt function is correct.
#' A claim consists of a claim name (e.g. "iss") and a claim value (e.g. "company A").
#' The function extracts the value for claim_name from the token and compares
#' the retrieved value with the claimed value.
#' Nested claims are supported up to one level, e.g. a claim value of
#' \code{list(name = "Alice", role = "admin")} is valid.
#' Nesting at a higher level is not implemented yet and will return FALSE.
#' @param claim_name name of the claim in the JWT, e.g. "iss".
#' @param claim_value value the claim should have to pass the test.
#' @param token JWT extracted with jose::jwt_decode_hmac.
#' @return TRUE if the claim is present in the JWT, FALSE if not. Returns FALSE
#' for higher order nested claims.
#' @export

check_claim <- function(claim_name, claim_value, token){

  token_claim_value <- tryCatch(token[[claim_name]], error = function (e) return(FALSE))

  if (is.list(token_claim_value) && is.list(claim_value)){
    # check that names of list are the same
    if (!setequal(names(token_claim_value), names(claim_value))){
      return(FALSE)
    }

    return(identical(token_claim_value[names(claim_value)], claim_value))
  }

  return(identical(token_claim_value, claim_value))
}
