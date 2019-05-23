# Load required packages -------------------------------------------------------
library(plumber)
library(gutenbergr)
library(stringr)
library(dplyr)

# Initialize plumber router ----------------------------------------------------
router <- plumber$new()

# Define filters ---------------------------------------------------------------
# logging filter
router$filter("logger", function (req) {
  cat(as.character(Sys.time()), "-",
      req$REQUEST_METHOD, req$PATH_INFO, "-",
      req$HTTP_USER_AGENT, "@", req$REMOTE_ADDR, "\n")

  # forward request
  forward()
})

# enable cors filter
router$filter("cors", function (req, res) {
  res$setHeader("Access-Control-Allow-Origin", "*")
  if (req$REQUEST_METHOD == "OPTIONS") {
    res$setHeader("Access-Control-Allow-Methods","*")
    res$setHeader("Access-Control-Allow-Headers",
                  req$HTTP_ACCESS_CONTROL_REQUEST_HEADERS)
    res$status <- 200
    return(list())
  } else {
    forward()
  }
})

# Define routes ----------------------------------------------------------------
# authentication route
router$handle("GET", "/authentication", function (req, res) {

})

# postings route
router$handle("GET", "/books", function (req, res) {
  gutenberg_works() %>%
    filter(str_detect(author, "Doyle, Arthur Conan")) %>%
    filter(has_text)
})

# postings secret route
router$handle("GET", "/text/<id>", function (req, res, id) {
  lines <- gutenberg_download(id, verbose = FALSE)
  paste(lines$text, collapse = " ")
})


router$run(host = "0.0.0.0", port = 9090)
