#' authenticate
#' @description \code{authenticate} takes one of the \code{is_authed_*} functions of sealr (or a custom function) as input.
#' If the request is authenticated / authorized, \code{authenticate} will forward the request to the next handler.
#' Hence, \code{authenticate} should only be used in plumber filters as it calls \code{plumber::forward}.
#'
#' @param req plumber request object
#' @param res plumber response object
#' @param is_authed_fun function. Function to check whether API call is authenticated / authorized.
#' Use any of sealr's is_authed_* functions or your own custom function. See Details for requirements for custom functions.
#' @param ... arguments to be passed down to the is_authed_fun function.
#' @return either TRUE (invisibly from plumber::forward()) or a list containing
#' HTTP status, HTTP status code, and a message (see details).
#' @importFrom plumber forward
#' @export
#' @details Custom is_authed_fun functions should return a list with the following elements:
#' \itemize{
#'   \item is_authed: TRUE or FALSE. Result of the check of is_authed_fun.
#'   \item status: character. short description of HTTP status code
#'   \item code: integer. HTTP status code
#'   \item message: character. Longer description.
#' }
#'
#' You can use the helper functions \code{\link{is_authed_return_list}} and \code{\link{is_authed_return_list_401}}
#' to generate those lists in your custom function.
#' @examples
#' \dontrun{
#'  pr$filter("sealr-jwt-filter", function(req, res){
#'    sealr::authenticate(req = req, res = res, sealr::is_authed_jwt, secret = "averylongsupersecretsecret")
#'  })
#' }
#' \dontrun{
#'  # define your own function somewhere
#'  is_authed_custom <- function(req, res, a, b){
#'   # some logic with request parameters (in req) and function parameters (a, b)
#'   if(TRUE){ # implement this
#'     # is authed
#'     return(sealr::is_authed_return_list(TRUE))
#'   } else {
#'     # not authed :(
#'     return(sealr::is_authed_return_list_401())
#'   }
#'  }
#'
#'  pr$filter("sealr-custom-filter", function(req, res){
#'   sealr::authenticate(req = req, res = res, sealr::is_authed_custom, a = 5, b = 4)
#'  })
#' }
#' @seealso \url{https://www.rplumber.io/docs/routing-and-input.html}
authenticate <- function(req, res, is_authed_fun, ...){

  # ensure that the user passed the request object
  if (missing(req))
    stop("Please pass the request object.")

  # ensure that the user passed the response object
  if (missing(res) == TRUE)
    stop("Please pass the response object.")

  if(!is.function(is_authed_fun)){
    stop("is_authed_fun must be a function.")
  }

  # call the specified is_authed_fun function
  is_authed_result <- do.call(is_authed_fun, args = list(req = req, res = res, ...))

  # do some simple consistency checks on the result
  if(!is.list(is_authed_result)){
    stop("is_authed_fun must return a list.")
  }

  # check is_authed value
  if(is.null(is_authed_result$is_authed) ||
     is.na(is_authed_result$is_authed) ||
     !is.logical(is_authed_result$is_authed)){
    stop(paste0("'is_authed' list element must either be TRUE or FALSE but it is: ",
                is_authed_result$is_authed))
  }

  # if auth not successful, return relevant list elements (HTTP status code etc)
  # to user
  if(!is_authed_result$is_authed){
    res$status <- is_authed_result$code

    http_response <- is_authed_result
    http_response$is_authed <- NULL
    return(http_response)
  }

  plumber::forward()
}
