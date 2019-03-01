#' JWT Strategy
#'
#' This function implements a JWT authentication strategy. The function can be used as a filter in front
#' of the routes. The strategy uses extracts the token from the HTTP Authorization header with the scheme 'bearer'.
#'
#' @param req Request object.
#' @param res Response object.
#' @param secret character. This should be the secret that use to sign your JWT. The secret is converted
#' to raw bytes in the function.
#' @param audience character. Check if user belongs to a certain audience.
#'
#' @importFrom stringr str_remove str_trim
#' @importFrom jose jwt_decode_hmac
#' @importFrom plumber forward
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

jwt <- function (req, res, secret, audience = NULL) {

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

  # check if audience correct
  if (!is.null(audience)) {
    if (audience != token$aud) {
      res$status <- 401
      return(list(status="Failed.",
                  code=401,
                  message="Authentication required."))
    }
  }

  # redirect to routes
  plumber::forward()
}
