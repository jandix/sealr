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

  ## validating the Google ID token -------------------------------------------------------------------------------------

  # get the header of the JWT
  # we need this to get the key id (kid) of the
  # key that was used by google to generate this JWT
  jwt_header <- tryCatch(jwt_split(token)$header,
                         error = function (e) NULL)

  if(is.null(jwt_header)) return(is_authed_return_list_401())

  # ensure that the jwt header includes kid
  if (!("kid" %in% names(jwt_header))) return(is_authed_return_list_401())

  # download public key file and find public key used for the jwt by matching the kid
  jwks <- download_jwks()
  index <- match_pub_key_in_jwks(jwks, jwt_header)

  if (length(index) != 1) {
    return(is_authed_return_list(FALSE, "Failed", 500,
                                 "Authentication Error. Hint: jwks_uri"))
  }

  pub_key <- parse_pub_key_in_jwks(jwks, index) # parse matched public key

  # use the key to decode the JWT payload
  payload <- tryCatch(jose::jwt_decode_sig(token, pub_key),
                      error = function (e) NULL)

  if (is.null(payload)) {
    return(is_authed_return_list_401())
  }

  # append jwt payload to request
  req$jwt_payload <- payload

  ## check jwt payload------------------------------------------------------------------------------------
  # google imposes several claims on their JWT that we need to check
  claims <- list(aud = client_id)

  if(!is.null(hd)){
    claims$hd = hd
  }

  if (is.null(payload$iss) ||
      !payload$iss %in% c("https://accounts.google.com", "accounts.google.com") || # check issuer
      !check_all_claims(payload, claims) ||  # check aud and (optionally) hd
      is_jwt_expired(payload)) { # check if token expired
    return(is_authed_return_list_401())
  }


  return(is_authed_return_list(TRUE))
}


download_jwks <- function(){
  # download public key file
  response <- httr::GET(jwks_uri)
  if (httr::http_error(response)) {
    return(NULL)
  }

  # match kid
  jwks <- jsonlite::fromJSON(httr::content(response, type = "text", encoding = "UTF-8"))$keys
  return(jwks)
}

match_pub_key_in_jwks <- function(jwks, jwt_header){
  index <- which(jwks$kid == jwt_header$kid)
  return(index)
}

parse_pub_key_in_jwks <- function(jwks, index){

  # parse public key
  pub_key <- jose::jwk_read(jwks[index, ])

  return(pub_key)
}
