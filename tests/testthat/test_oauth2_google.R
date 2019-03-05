testthat::context("Test OAuth2 Google Strategy")

# TEST MISSING INPUTS ------------------------------------------------------------------------------------

testthat::test_that("test that the function requires request object", {
  testthat::expect_error(sealr::oauth2_google(res = list(), client_id = "xxx"),
                         regexp = "Please pass the request object.")
})

testthat::test_that("test that the function response response object", {
  testthat::expect_error(sealr::oauth2_google(req = list(), client_id = "xxx"),
                         regexp = "Please pass the response object.")
})

testthat::test_that("test that the function requires client_id", {
  testthat::expect_error(sealr::oauth2_google(req = list(), res = list()),
                         regexp = "Please pass the Google client id.")
})

# TEST FUNCTION ------------------------------------------------------------------------------------------

testthat::test_that("test that the function requires HTTP_AUTHORIZATION header", {
  # test data
  test_req <- list()
  test_res <- list()
  client_id <- "xxx"

  res <- sealr::oauth2_google(req = test_req,
                              res = test_res,
                              client_id = test_client_id)
  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")
})

testthat::test_that("test that the function requires valid HTTP_AUTHORIZATION", {
  # test data
  test_req <- list(HTTP_AUTHORIZATION = "xxx.xxx.xxx")
  test_res <- list()
  client_id <- "xxx"

  res <- sealr::oauth2_google(req = test_req,
                              res = test_res,
                              client_id = test_client_id)
  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")
})

testthat::test_that("test that the function requires valid HTTP_AUTHORIZATION that matches google key", {
  # test data
  key <- openssl::rsa_keygen()
  pub_key <- as.list(key)$pubkey
  token <- jose::jwt_claim(name = "Franz",
                     uid = 509)
  jwt <- jose::jwt_encode_sig(token, key)
  test_req <- list(HTTP_AUTHORIZATION = jwt)
  test_res <- list()
  client_id <- "xxx"

  res <- sealr::oauth2_google(req = test_req,
                              res = test_res,
                              client_id = test_client_id)
  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")
})
