http_response_list <- function(status, status_code, message){
  return(list(
    status = status,
    code = status_code,
    message = message))
}

auth_required_response <- function(){
  return(http_response_list("Failed.", 401, "Authentication required."))
}

