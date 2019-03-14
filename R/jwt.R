#' JWT Strategy
#'
#' This function implements a JWT authentication strategy. The function can be used as a filter in front
#' of the routes. The strategy uses extracts the token from the HTTP Authorization header with the scheme 'bearer'.
#'
#' @param req Request object.
#' @param res Response object.
#' @param secret character. This should be the secret that use to sign your JWT. The secret is converted
#' to raw bytes in the function.
#' @param claims named list. Claims that should be checked in the JWT. Claims can be nested lists themselves.
#'
#' @importFrom stringr str_remove str_trim
#' @importFrom jose jwt_decode_hmac
#' @importFrom plumber forward
#'
#' @examples
#' \dontrun{
#' pr$filter("sealr-jwt", function (req, res) {
#'   sealr::jwt(req = req, res = res, secret = secret, claims = list(iss = "plumberapi", user = list(name = "Alice", id = "1234")))
#' })
#' }
#'
#' @export
#'

jwt <- function (req, res, secret, claims = NULL) {

  # ensure that the user passed the request object
  if (missing(req) == TRUE)
    stop("Please pass the request object.")

  # ensure that the user passed a secret
  if (missing(secret) == TRUE)
    stop("Please define a secret.")

  # ensure that the secret is not an empty string
  if (nchar(secret) < 1)
    warning("Your secret is empty. This is a possible security risk.")

  # convert secret to bytes
  secret <- charToRaw(secret)

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
  token <- tryCatch(jose::jwt_decode_hmac(req$HTTP_AUTHORIZATION, secret = secret),
                   error = function (e) NULL)

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
#' This function checks that all claims passed in the \code{claims} argument of the jwt function are
#' correct.
#' @param token JWT extracted with jose::jwt_decode_hmac.
#' @param claims named list of claims to check in the JWT. Claims can be nested.
#' @return TRUE if the all claims are present in the JWT, FALSE if not.
#' @importFrom purrr map2_lgl
#' @export

check_all_claims <- function(token, claims){

  claim_values <- claims
  claim_names <- names(claims)

  results <- purrr::map2_lgl(claim_names, claim_values, check_claim, token = token)
  return(all(results))
}


#'
#' This function checks that a claim passed to the jwt function is valid in the
#' given JWT.
#' A claim consists of a claim name (e.g. "iss") and a claim value (e.g. "company A").
#' Claim values can also be named lists themselves.
#' The function recursively extracts the value for claim_name from the token.
#' If the claim_value is atomic, it compares
#' the retrieved value with the claimed value. Otherwise, it applies check_claim
#' to claim_value recursively.
#' @param claim_name name of the claim in the JWT, e.g. "iss".
#' @param claim_value value the claim should have to pass the test.
#' @param token JWT extracted with jose::jwt_decode_hmac.
#' @return TRUE if the claim is present in the JWT, FALSE if not.
#' @importFrom purrr vec_depth map2_lgl
#' @export

check_claim <- function(claim_name, claim_value, token){

  # recursion at end, claim_value is just atomic (e.g. "Alice")
  if(purrr::vec_depth(claim_value) == 1){

    token_claim_value <- token[[claim_name]]
    # claim does not exist in token
    if (is.null(token_claim_value)) {
      return(FALSE)
    }

    # compare token value with expected value
    return(identical(token_claim_value, claim_value))

  } else {
    # claim_value is a list --> recurse
    # cannot subset token because claim_name does not exist in token
    # -> wrong claim_value
    if (!claim_name %in% names(token)){
      return(FALSE)
    }
    # recursively apply to all elements of claim_value
    return(all(c(purrr::map2_lgl(names(claim_value), claim_value, check_claim,
                                 token = token[[claim_name]]))))
  }
}

