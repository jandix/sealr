context("Test authenticate function")

# ERRORS ----------------------------------------------------------------------
testthat::test_that("test that the function throws error if is_authed_fun is missing.", {
  testthat::expect_error(sealr::authenticate(req = list(), res = list()),
                         regexp = "\"is_authed_fun\" is missing")
})

testthat::test_that("test that the function throws error if is_authed_fun is not a function.", {
  testthat::expect_error(sealr::authenticate(req = list(), res = list(),
                                             is_authed_fun = c("this is not a function")),
                         regexp = "is_authed_fun must be a function")
})

# MOCK IS_AUTHED_FUN -----------------------------------------------------------

testthat::test_that("test that function throws error if is_authed_fun does not return a list.", {
  testthat::expect_error(sealr::authenticate(req = list(), res = list(),
                                             is_authed_fun = function(req, res) {
                                               return("this is not a list")
                                             }),
                         regexp = "is_authed_fun must return a list")
})

testthat::test_that("test that function throws error if is_authed_fun returns a string.", {
  testthat::expect_error(sealr::authenticate(req = list(), res = list(),
                                             is_authed_fun = function(req, res) {
                                               return(list(is_authed = "this is not true or false"))
                                             }),
                         regexp = "'is_authed' list element must either be TRUE or FALSE ")
})

testthat::test_that("test that function throws error if is_authed_fun returns NA.", {
  testthat::expect_error(sealr::authenticate(req = list(), res = list(),
                                             is_authed_fun = function(req, res) return(list(is_authed = NA))),
                         regexp = "'is_authed' list element must either be TRUE or FALSE ")
})

# TEST WITH JWT FUNCTION -------------------------------------------------------

testthat::test_that("test that function returns 401 if is_authed_jwt returns FALSE", {

  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID = "Alice",
                                                            exp = as.numeric(Sys.time() - 1000)),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  # is_authed_jwt will return FALSE because token is expired.
  res <- sealr::authenticate(req = test_req, res = test_res,
                             is_authed_fun = sealr::is_authed_jwt, secret = test_secret)
  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")
})

testthat::test_that("test that function returns TRUE if is_authed_jwt is TRUE", {
  # plumber::forward() invisibly returns true

  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID = "Alice"),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  testthat::expect_true(sealr::authenticate(req = test_req, res = test_res,
                             is_authed_fun = sealr::is_authed_jwt, secret = test_secret))
})

testthat::test_that("test that function returns TRUE if custom function is TRUE", {
  # plumber::forward() invisibly returns true

  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID = "Alice"),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  is_authed_custom <- function(req, res, x) return(list(is_authed = x > 4))
  testthat::expect_true(sealr::authenticate(req = test_req, res = test_res,
                                            is_authed_fun = is_authed_custom, x = 5))
})
