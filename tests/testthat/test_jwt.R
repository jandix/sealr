testthat::context("Test JWT Strategy")

# TEST MISSING INPUTS ------------------------------------------------------------------------------------
testthat::test_that("test that the function requires request object", {
  testthat::expect_error(sealr::jwt(secret = "YAMYAMYAM"),
                         regexp = "Please pass the request object.")
})

testthat::test_that("test that the function requires secret or public key", {
  testthat::expect_error(sealr::jwt(res = list(), req = list()),
                         regexp = "either a secret or a public key.")
})

testthat::test_that("test that the function does not accept secret and public key", {
  testthat::expect_error(sealr::jwt(res = list(), req = list(), secret = "1223", pubkey = "key"),
                         regexp = "either a secret or a public key, not both.")
})

testthat::test_that("test that the function requires HTTP Authorization header", {
  res <- sealr::jwt(req = list(),
                    res = list(),
                    secret = "YAMYAMYAM")
  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")
})

# TEST WARNINGS ------------------------------------------------------------------------------------------
testthat::test_that("test the function warns if the secret is empty", {
  testthat::expect_warning(sealr::jwt(req = list(), res = list(), secret = ""),
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
  testthat::expect_equal(sealr::jwt(req = test_req,
                                    res = test_res,
                                    secret = test_secret), TRUE)
})

testthat::test_that("test that a valid JWT with audience goes through the function.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID= "Alice",
                                                            audience = "user"),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  # plumber::forward at end of jwt() invisibly returns TRUE
  testthat::expect_equal(sealr::jwt(req = test_req,
                                    res = test_res,
                                    secret = test_secret,
                                    claims = list(audience = "user")), TRUE)
})

testthat::test_that("test that a valid JWT with wrong audience generates 401.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID= "Alice",
                                                            audience = "admin"),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  # plumber::forward at end of jwt() invisibly returns TRUE
  res <- sealr::jwt(req = test_req,
                    res = test_res,
                    secret = test_secret,
                    claims = list(audience = "user"))
  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")
})

testthat::test_that("test that an invalid JWT generates 401.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID = "Alice"),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()
  test_secret <- "BRUMMBRUMM"

  # plumber::forward at end of jwt() invisibly returns TRUE
  res <- sealr::jwt(req = test_req,
                    res = test_res,
                    secret = test_secret)
  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")
})

testthat::test_that("test that an invalid value for JWT generates 401.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_req <- list(HTTP_AUTHORIZATION = "somethingnotjwttokenlike")
  test_res <- list()

  # plumber::forward at end of jwt() invisibly returns TRUE
  res <- sealr::jwt(req = test_req,
                    res = test_res,
                    secret = test_secret)
  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")
})

testthat::test_that("test that decoding with public key works.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_key <- openssl::rsa_keygen()
  test_jwt <- jose::jwt_encode_sig(claim = jose::jwt_claim(userID = "Alice"),
                                    key = test_key)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  # plumber::forward at end of jwt() invisibly returns TRUE
  testthat::expect_equal(sealr::jwt(req = test_req,
                                    res = test_res,
                                    pubkey = as.list(test_key)$pubkey), TRUE)
})


testthat::test_that("test that an invalid public key generates 401.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_key <- openssl::rsa_keygen()
  test_jwt <- jose::jwt_encode_sig(claim = jose::jwt_claim(userID = "Alice"),
                                   key = test_key)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  res <- sealr::jwt(req = test_req,
                    res = test_res,
                    pubkey = "thisisnotapublickey")
  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")
})

testthat::test_that("test that the wrong public key generates 401.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_key <- openssl::rsa_keygen()
  test_wrong_key <- openssl::rsa_keygen()
  test_jwt <- jose::jwt_encode_sig(claim = jose::jwt_claim(userID = "Alice"),
                                   key = test_key)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  res <- sealr::jwt(req = test_req,
                    res = test_res,
                    pubkey = as.list(test_wrong_key)$pubkey)
  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")
})

testthat::test_that("test that an expired JWT generates 401.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID = "Alice",
                                                            exp = as.numeric(Sys.time() - 1000)),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  res <- sealr::jwt(req = test_req,
                    res = test_res,
                    secret = test_secret)

  testthat::expect_equal(res$status, "Failed.")
  testthat::expect_equal(res$code, 401)
  testthat::expect_equal(res$message, "Authentication required.")

})

testthat::test_that("test that an unexpired JWT goes through.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID = "Alice",
                                                            exp = as.numeric(Sys.time() + 1000)),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  # plumber::forward at end of jwt() invisibly returns TRUE
  testthat::expect_true(sealr::jwt(req = test_req,
                                   res = test_res,
                                   secret = test_secret))

})
