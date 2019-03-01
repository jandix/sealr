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

oauth2_google <- function (req, res, access_token, refresh_token) {

  # check if token is valid

  # try if access token is still working

  # try to refresh token using refresh token

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
