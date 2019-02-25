testthat::context("Test JWT Strategy")

# TEST MISSING INPUTS -------------------------------------------------------------------------------------
testthat::test_that("test that the function requires request object", {
  testthat::expect_error(passport::jwt(secret = "YAMYAMYAM"),
                         regexp = "Please pass the request object.")
})

testthat::test_that("test that the function requires secret", {
  testthat::expect_error(passport::jwt(req = list()),
                         regexp = "Please define a secret.")
})


testthat::test_that("test that the function requires HTTP Authorization header", {
  test_res <- passport::jwt(res = list(),
                                req = list(),
                                secret = "YAMYAMYAM")
  testthat::expect_equal(test_res$code, 401)
  testthat::expect_equal(test_res$message, "Authentication required.")
})

# TEST WARNINGS ------------------------------------------------------------------------------------------
testthat::test_that("test the function warns if the secret is empty", {
  testthat::expect_warning(passport::jwt(req = list(), res = list(), secret = ""),
                           regexp = "Your secret is empty. This is a possible security risk.")
})

# TEST FUNCTION ------------------------------------------------------------------------------------------
testthat::test_that("test that a valid JWT goes through the function.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID = "Alice"),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  # plumber::forward at end of jwt() invisibly returns TRUE
  testthat::expect_equal(jwt(test_req, test_res, test_secret), TRUE)
})
