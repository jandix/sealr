http_response_list <- function(status, status_code, message){
  return(list(
    status = status,
    code = status_code,
    message = message))
}

auth_required_response <- function(){
  return(http_response_list("Failed.", 401, "Authentication required."))
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
  list(type = type, keysize = keysize, data = data, sig = sig, payload = payload)
}
