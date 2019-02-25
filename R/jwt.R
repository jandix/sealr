#' JWT Strategy
#'
#' This function implements a JWT authentication strategy. The function can be used as a filter in front
#' of the routes. The strategy uses extracts the token from the HTTP Authorization header with the scheme 'bearer'.
#'
#' @param req Request object.
#' @param res Response object.
#' @param secret character. This should be the secret that use to sign your JWT. The secret is converted
#' to raw bytes in the function.
#'
#' @usage passport::jwt()
#'
#' @importFrom stringr str_remove str_trim
#' @importFrom jose jwt_decode_hmac
#' @importFrom plumber forward
#'
#' @examples
#' \dontrun{
#' pr$filter("passport-jwt", function (req, res) {
#'   passport::jwt(req = req, res = res, secret = secret)
#' })
#' }
#'
#' @export
#'

jwt <- function (req, res, secret) {

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
  auth <- tryCatch(jose::jwt_decode_hmac(req$HTTP_AUTHORIZATION, secret = secret),
                   error = function (e) NULL)

  # if token not valid send error
  if (is.null(auth)) {
    res$status <- 401
    return(list(status="Failed.",
                code=401,
                message="Authentication required."))
  }

  # redirect to routes
  plumber::forward()
}
