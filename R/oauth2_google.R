#' Google OAuth2.0 / OpenID Connect Strategy
#'
#' @description  \code{is_authed_oauth2_google} checks whether a Google access token
#' obtained via Google's OpenID Connect (an implementation of OAuth 2.0 for
#' authentication) passed as part of the HTTP request is valid.
#' The function can be passed to \code{\link{authenticate}}'s \code{is_authed_fun}
#' argument or it can be used standalone in any plumber endpoint.
#' \code{is_authed_oauth2_google} extracts the token from the HTTP Authorization header with the scheme 'bearer'.
#' @param req plumber request object
#' @param res plumber response object
#' @param token_location character. Location of token. Either "header" or "cookie".
#' See \code{\link{get_token_from_req}} for details.
#' @param client_id character. Google client ID. See \href{https://developers.google.com/identity/protocols/OpenIDConnect#authenticationuriparameters}{docs for Google OpenID Connect}
#' @param hd character. hosted domain. Default NULL. See \href{https://developers.google.com/identity/protocols/OpenIDConnect#authenticationuriparameters}{docs for Google OpenID Connect}.
#' @param jwks_uri character. JSON Web Key URI. See \href{https://developers.google.com/identity/protocols/OpenIDConnect#discovery}{docs for Google OpenID Connect}.
#'
#' @importFrom stringr str_remove str_trim
#' @importFrom jose jwt_decode_sig
#' @importFrom anytime anytime
#' @importFrom httr GET content
#' @importFrom jsonlite fromJSON
#' @importFrom plumber forward
#' @return list with the following elements:
#' \itemize{
#'   \item is_authed: TRUE or FALSE. Result of the check whether the access token is valid.
#'   \item status: character. Optional. Short description of HTTP status code.
#'   \item code: integer. Optional. HTTP status code.
#'   \item message: character. Optional. Longer description.
#' }
#'
#' @examples
#' \dontrun{
#' pr$filter("sealr-google-oauth", function (req, res) {
#'   sealr::authenticate(req = req, res = res,
#'                       is_authed_fun = is_authed_oauth2_google,
#'                       client_id = Sys.getenv("GOOGLE_CLIENT_ID"))
#' })
#' }
#'
#' @export
#' @seealso \url{https://developers.google.com/identity/protocols/OpenIDConnect}

is_authed_oauth2_google <- function (req,
                           res,
                           token_location,
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

  if (missing(token_location) == TRUE)
    stop("Please specify a token location.")

  # ensure that the user passed the client_id
  if (missing(client_id) == TRUE)
    stop("Please pass the Google client id.")

  ## parse token ----------------------------------------------------------------
  if (token_location == "header") {
    # ensure that the request includes HTTP_AUTHORIZATION header
    if (!("HTTP_AUTHORIZATION" %in% names(req))) {
      return(is_authed_return_list_401())
    }
  }

  # get token from request object
  token <- get_token_from_req(req, token_location)

  # remove "Bearer" part from token
  token <- clean_bearer_token(token)

  # split the JWT token into its components
  jwt <- tryCatch(jwt_split(token),
                  error = function (e) NULL)

  if(is.null(jwt)) return(is_authed_return_list_401())

  ## check signature -------------------------------------------------------------------------------------

  # ensure that the jwt header includes kid
  if (!("kid" %in% names(jwt$header))) {
    return(is_authed_return_list_401())
  }

  # download public key file
  response <- httr::GET(jwks_uri)
  if (httr::http_error(response)) {
    return(is_authed_return_list_401())
  }

  # match kid
  jwks <- jsonlite::fromJSON(httr::content(response, type = "text", encoding = "UTF-8"))$keys
  index <- which(jwks$kid == jwt$header$kid)

  if (length(index) == 0) {
    return(is_authed_return_list(FALSE, "Failed", 500,
                                 "Authentication Error. Hint: jwks_uri"))
  }

  # parse public key
  pub_key <- jose::jwk_read(jwks[index, ])

  # check signature
  payload <- tryCatch(jose::jwt_decode_sig(token, pub_key),
                      error = function (e) NULL)

  # if token not valid send error
  if (is.null(payload)) {
    return(is_authed_return_list_401())
  }

  # append jwt payload to request
  req$jwt_payload <- payload

  ## check jwt payload------------------------------------------------------------------------------------

  # check if iss is correct
  if (!stringr::str_detect(payload$iss, "https://accounts.google.com||accounts.google.com")) {
    return(is_authed_return_list_401())
  }

  # check if client id matches
  if (payload$aud != client_id) {
    return(is_authed_return_list_401())
  }

  # check if token expired
  if (is_jwt_expired(payload)) {
    return(is_authed_return_list_401())
  }

  # check if hd is valid
  if (!is.null(hd)) {
    if (payload$hd != hd) {
      return(is_authed_return_list_401())
    }
  }

  return(is_authed_return_list(TRUE))
}

