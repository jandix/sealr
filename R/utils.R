#' clean_bearer_token
#' @description helper function that removes 'Bearer' from a bearer scheme token and trims whitespace.
#' @param token character. The token to be handled.
#' @return the cleaned token.
clean_bearer_token <- function(token){
  token <- stringr::str_remove(token, "Bearer\\s")
  token <- stringr::str_trim(token)
  return(token)
}


#' get_token_from_req
#' @description helper function that extracts the token from the request object based
#' on the token_location argument.
#' @param req plumber request object.
#' @param token_location character. Location of token. Either "header" or "cookie". See details.
#' @details Specify "header" for the \code{token_location} argument if the token
#' is stored in the HTTP Authorization header. Specify "cookie" if the token is stored as an
#' encrypted session cookie called "token" (note that unencrypted cookies are not supported).
#' See the \href{https://www.rplumber.io/docs/rendering-and-output.html#encrypted-cookies}{plumber docs}
#' for how to set an encrypted cookie.
#' @return token
#' @seealso \url{https://www.rplumber.io/docs/rendering-and-output.html#encrypted-cookies}
get_token_from_req <- function(req, token_location){
  # get token from request object based on token_location argument
  if (token_location == "header") {
    token <- req$HTTP_AUTHORIZATION
  } else if (token_location == "cookie") {
    token <- req$session$token
  } else {
    stop("Invalid token_location argument. Must be either 'header' or 'cookie'.")
  }
  return(token)
}


#' Small convenience function that wraps \code{is_authed_return_list} for the
#' common case in this package of a "401 - Authentication required" response
#' @export
is_authed_return_list_401 <- function(){
  is_authed_return_list(FALSE, "Failed.", 401, "Authentication required.")
}

#' generates a list used as return value by the is_authed_* functions
#' @param is_authed logical. Should be either TRUE or FALSE.
#' @param status_description character. Short description of the HTTP status code, e.g. 'Failed' for 401. Default NULL.
#' @param status_code integer. HTTP status code to return to the user. Default NULL.
#' @param message character. Longer description to return to the user. Default NULL.
#' @return list with the following elements: is_authed, status, code, message.
#' @export
is_authed_return_list <- function(is_authed, status_description = NULL,
                                  status_code = NULL, message = NULL){
  list(
    is_authed = is_authed,
    status = status_description,
    code = status_code,
    message = message
  )
}

#' adapted from https://github.com/jeroen/jose/blob/master/R/jwt.R until the function is exported in
#' CRAN version (version on github already exports this function)
#' @param jwt raw. JWT.
#' @importFrom jsonlite fromJSON
#' @importFrom jose base64url_decode
jwt_split <- function(jwt){
  input <- strsplit(jwt, ".", fixed = TRUE)[[1]]
  stopifnot(length(input) %in% c(2,3))
  header <- jsonlite::fromJSON(rawToChar(jose::base64url_decode(input[1])))
  stopifnot(toupper(header$typ) == "JWT")
  if(is.na(input[3])) input[3] = ""
  sig <- jose::base64url_decode(input[3])
  header <- jsonlite::fromJSON(rawToChar(jose::base64url_decode(input[1])))
  payload <- jsonlite::fromJSON(rawToChar(jose::base64url_decode(input[2])))
  data <- charToRaw(paste(input[1:2], collapse = "."))
  if(!grepl("^none|[HRE]S(256|384|512)$", header$alg))
    stop("Invalid algorithm: ", header$alg)
  keysize <- as.numeric(substring(header$alg, 3))
  type <- match.arg(substring(header$alg, 1, 1), c("HMAC", "RSA", "ECDSA"))
  list(type = type, keysize = keysize, data = data, sig = sig, payload = payload, header = header)
}
