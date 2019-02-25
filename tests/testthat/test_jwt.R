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

# TEST WARNINGS ------------------------------------------------------------------------------------------
testthat::test_that("test that the secret is empty", {
  testthat::expect_warning(passport::jwt(req = list(), res = list(), secret = ""),
                           regexp = "Your secret is empty. This is a possible security risk.")
})

# TEST FUNCTION ------------------------------------------------------------------------------------------
