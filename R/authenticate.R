#' authenticate
#' \code{authenticate} should be used in context of
#'
#' @param strategy character. Must be one of: \code{jwt, google}.
#' @param req plumber request object
#' @param res plumber response object
#' @param ... arguments to be passed down to the is_authed_ function.
#' @importFrom plumber forward
#' @export
authenticate <- function(strategy, req, res, ...){

  function_map <- list(jwt = sealr::is_authed_jwt,
                       google = sealr::is_authed_oauth2_google)

  strategies <- names(function_map)

  if(length(strategy) > 1) {
    stop("You can only specify one strategy.")
  }

  if(!strategy %in% strategies){
    stop(paste0("strategy argument must be one of: ",
                paste(strategies, collapse = ", ")))
  }

  is_authed <- do.call(function_map[[strategy]], args = c(req, res, ...))

  if(!is_authed){
    sealr::auth_required_response()
  }

  plumber::forward()
}


