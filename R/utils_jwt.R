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
