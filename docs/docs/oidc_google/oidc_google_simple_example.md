---
output: 
  md_document:
    preserve_yaml: true
title: OAuth2 Google Simple Example
weight: 1
---

Install the packages
--------------------

Install the following packages if you haven't already:

-   sealr
-   httr
-   jose
-   jsonlite

define a new plumber router
---------------------------

    pr <- plumber::plumber$new()

    pr$handle("GET", "/", function (req, res, code = NULL) {

    })

define authentication route to issue web tokens (exclude "sealr-jwt" filter using preempt)
------------------------------------------------------------------------------------------

    pr$handle("GET", "/authentication", function (req, res) {
      url <- "https://accounts.google.com/o/oauth2/v2/auth"

      query <- list(client_id = "62291147513-pubf19de15prks9p2eij7hloteug5h5d.apps.googleusercontent.com",
                    redirect_uri = "http://localhost:9090/authentication/redirect",
                    scope = "https://www.googleapis.com/auth/userinfo.profile",
                    response_type = "code")
      auth_url <- httr::parse_url(url = url)
      auth_url$query <- query
      auth_url <- httr::build_url(auth_url)
      res$status <- 301
      res$setHeader("Location", auth_url)
      return()
    })

define authentication route to issue web tokens (exclude "sealr-jwt" filter using preempt)
------------------------------------------------------------------------------------------

    pr$handle("GET", "/authentication/redirect", function (req, res, code = NULL, error = NULL) {
      token_url <- "https://www.googleapis.com/oauth2/v4/token"
      body <- list(
        code = code,
        client_id = "62291147513-pubf19de15prks9p2eij7hloteug5h5d.apps.googleusercontent.com",
        client_secret = "0iE21iyz1htfHPtOw21zWcw6",
        redirect_uri = "http://localhost:9090/authentication/redirect",
        grant_type = "authorization_code"
      )
      response <- httr::POST(token_url, body = body)
      parsed_response <- jsonlite::fromJSON(httr::content(response, type = "text"))
      return(parsed_response)
    })

start API server
----------------

    pr$run(host="0.0.0.0", port=9090)
