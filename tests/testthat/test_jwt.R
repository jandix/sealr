testthat::context("Test JWT Strategy")

# TEST MISSING INPUTS ------------------------------------------------------------------------------------
testthat::test_that("test that the function requires request object", {
  testthat::expect_error(sealr::is_authed_jwt(secret = "YAMYAMYAM"),
                         regexp = "Please pass the request object.")
})

testthat::test_that("test that the function requires secret or public key", {
  testthat::expect_error(sealr::is_authed_jwt(res = list(), req = list(), token_location = "header"),
                         regexp = "either a secret or a public key.")
})

testthat::test_that("test that the function requires token_location", {
  testthat::expect_error(sealr::is_authed_jwt(req = list(), res = list()),
                         regexp = "Please specify a token location.")
})

testthat::test_that("test that the function does not accept secret and public key", {
  testthat::expect_error(sealr::is_authed_jwt(res = list(), req = list(),
                                              token_location = "header",
                                              secret = "1223", pubkey = "key"),
                         regexp = "either a secret or a public key, not both.")
})

testthat::test_that("test that the function requires HTTP Authorization header", {
  res <- sealr::is_authed_jwt(req = list(),
                              res = list(),
                              token_location = "header",
                              secret = "YAMYAMYAM")
  testthat::expect_false(res$is_authed)
})

testthat::test_that("test the function throws error if the secret is empty", {
  testthat::expect_error(sealr::is_authed_jwt(req = list(), res = list(),
                                              token_location = "header", secret = ""),
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

  res <- sealr::is_authed_jwt(req = test_req,
                              res = test_res,
                              token_location = "header",
                              secret = test_secret)
  testthat::expect_true(res$is_authed)
})

testthat::test_that("test that a valid JWT with audience goes through the function.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID= "Alice",
                                                            audience = "user"),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  res <- sealr::is_authed_jwt(req = test_req,
                              res = test_res,
                              token_location = "header",
                              secret = test_secret,
                              claims = list(audience = "user"))

  testthat::expect_true(res$is_authed)
})

testthat::test_that("test that a valid JWT with wrong audience returns FALSE.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID= "Alice",
                                                            audience = "admin"),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  res <- sealr::is_authed_jwt(req = test_req,
                              res = test_res,
                              token_location = "header",
                              secret = test_secret,
                              claims = list(audience = "user"))
  testthat::expect_false(res$is_authed)
  testthat::expect_equal(res$code, 401)

})

testthat::test_that("test that an invalid JWT returns FALSE.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID = "Alice"),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()
  test_secret <- "BRUMMBRUMM"

  res <- sealr::is_authed_jwt(req = test_req,
                              res = test_res,
                              token_location = "header",
                              secret = test_secret)
  testthat::expect_false(res$is_authed)
  testthat::expect_equal(res$code, 401)

})

testthat::test_that("test that an invalid value for JWT returns FALSE.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_req <- list(HTTP_AUTHORIZATION = "somethingnotjwttokenlike")
  test_res <- list()

  res <- sealr::is_authed_jwt(req = test_req,
                              res = test_res,
                              token_location = "header",
                              secret = test_secret)
  testthat::expect_false(res$is_authed)
  testthat::expect_equal(res$code, 401)

})

testthat::test_that("test that decoding with public key works.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_key <- openssl::rsa_keygen()
  test_jwt <- jose::jwt_encode_sig(claim = jose::jwt_claim(userID = "Alice"),
                                    key = test_key)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  res <- sealr::is_authed_jwt(req = test_req,
                              res = test_res,
                              token_location = "header",
                              pubkey = as.list(test_key)$pubkey)
  testthat::expect_true(res$is_authed)

})


testthat::test_that("test that an invalid public key generates 401.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_key <- openssl::rsa_keygen()
  test_jwt <- jose::jwt_encode_sig(claim = jose::jwt_claim(userID = "Alice"),
                                   key = test_key)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  res <- sealr::is_authed_jwt(req = test_req,
                              res = test_res,
                              token_location = "header",
                              pubkey = "thisisnotapublickey")
  testthat::expect_false(res$is_authed)
  testthat::expect_equal(res$code, 401)

})

testthat::test_that("test that the wrong public key returns FALSE.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_key <- openssl::rsa_keygen()
  test_wrong_key <- openssl::rsa_keygen()
  test_jwt <- jose::jwt_encode_sig(claim = jose::jwt_claim(userID = "Alice"),
                                   key = test_key)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  res <- sealr::is_authed_jwt(req = test_req,
                              res = test_res,
                              token_location = "header",
                              pubkey = as.list(test_wrong_key)$pubkey)
  testthat::expect_false(res$is_authed)
  testthat::expect_equal(res$code, 401)

})

testthat::test_that("test that an expired JWT returns FALSE.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID = "Alice",
                                                            exp = as.numeric(Sys.time() - 1000)),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  res <- sealr::is_authed_jwt(req = test_req,
                              res = test_res,
                              token_location = "header",
                              secret = test_secret)
  testthat::expect_false(res$is_authed)
  testthat::expect_equal(res$code, 401)

})

testthat::test_that("test that an unexpired JWT goes through.", {
  # test data
  test_secret <- "YAMYAMYAM"
  test_jwt <- jose::jwt_encode_hmac(claim = jose::jwt_claim(userID = "Alice",
                                                            exp = as.numeric(Sys.time() + 1000)),
                                    secret = test_secret)
  test_req <- list(HTTP_AUTHORIZATION = test_jwt)
  test_res <- list()

  res <- sealr::is_authed_jwt(req = test_req,
                              res = test_res,
                              token_location = "header",
                              secret = test_secret)
  testthat::expect_true(res$is_authed)

})
