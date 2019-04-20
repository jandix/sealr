testthat::context("Test OAuth2 Google Strategy")

# TEST MISSING INPUTS ------------------------------------------------------------------------------------

testthat::test_that("test that the function requires request object", {
  testthat::expect_error(sealr::is_authed_oidc_google(res = list(), client_id = "xxx"),
                         regexp = "Please pass the request object.")
})

testthat::test_that("test that the function requires response object", {
  testthat::expect_error(sealr::is_authed_oidc_google(req = list(), client_id = "xxx"),
                         regexp = "Please pass the response object.")
})

testthat::test_that("test that the function requires token_location", {
  testthat::expect_error(sealr::is_authed_oidc_google(req = list(), res = list(),
                                                        client_id = "xxx"),
                         regexp = "Please specify a token location.")
})

testthat::test_that("test that the function requires client_id", {
  testthat::expect_error(sealr::is_authed_oidc_google(req = list(), res = list(), token_location = "header"),
                         regexp = "Please pass the Google client id.")
})

# TEST FUNCTION ------------------------------------------------------------------------------------------

testthat::test_that("test that the function requires HTTP_AUTHORIZATION header if token_location is 'header'.", {
  # test data
  test_req <- list()
  test_res <- list()
  client_id <- "xxx"

  res <- sealr::is_authed_oidc_google(req = test_req,
                                        res = test_res,
                                        token_location = "header",
                                        client_id = test_client_id)
  testthat::expect_false(res$is_authed)
})

testthat::test_that("test that the function fails if token is invalid", {
  # test data
  test_req <- list(HTTP_AUTHORIZATION = "xxx.xxx.xxx")
  test_res <- list()
  client_id <- "xxx"

  res <- sealr::is_authed_oidc_google(req = test_req,
                                        res = test_res,
                                        token_location = "header",
                                        client_id = test_client_id)
  testthat::expect_false(res$is_authed)
})

# TEST FUNCTION WITH HELP OF MOCKING ---------------------------------------------
testthat::test_that("test that the function works with all arguments", {

  test_res <- list()
  test_client_id <- "xxx"
  test_hd = "thisismyhd"
  test_kid = "thisismykid"

  # public key to to be used as signature for JWT
  key <- openssl::rsa_keygen()
  pub_key <- as.list(key)$pubkey

  # generate JWT
  token <- jose::jwt_claim(name = "Franz",
                           uid = 509,
                           aud = test_client_id,
                           iss = "https://accounts.google.com",
                           hd = test_hd)

  jwt <- jose::jwt_encode_sig(token, key, header = list(kid = test_kid))
  test_req <- list(HTTP_AUTHORIZATION = jwt)

  mockery::stub(sealr::is_authed_oidc_google, "download_jwks", data.frame())
  mockery::stub(sealr::is_authed_oidc_google, "match_kid_in_jwks", 1)
  mockery::stub(sealr::is_authed_oidc_google, "parse_pub_key_in_jwks", pub_key)


  res <- sealr::is_authed_oidc_google(req = test_req,
                                        res = test_res,
                                        token_location = "header",
                                        client_id = test_client_id,
                                        hd =  test_hd)
  testthat::expect_true(res$is_authed)
})

testthat::test_that("test that the function works without optional hd check", {

  # public key to to be used as signature for JWT
  key <- openssl::rsa_keygen()
  pub_key <- as.list(key)$pubkey

  # test data
  test_res <- list()
  test_kid = "thisismykid"
  test_client_id = "xxx"

  # generate JWT
  token <- jose::jwt_claim(name = "Franz",
                           uid = 509,
                           aud = test_client_id,
                           iss = "https://accounts.google.com")

  jwt <- jose::jwt_encode_sig(token, key, header = list(kid = test_kid))
  test_req <- list(HTTP_AUTHORIZATION = jwt)

  mockery::stub(sealr::is_authed_oidc_google, "download_jwks", data.frame())
  mockery::stub(sealr::is_authed_oidc_google, "match_kid_in_jwks", 1)
  mockery::stub(sealr::is_authed_oidc_google, "parse_pub_key_in_jwks", pub_key)


  res <- sealr::is_authed_oidc_google(req = test_req,
                                        res = test_res,
                                        token_location = "header",
                                        client_id = test_client_id)
  testthat::expect_true(res$is_authed)
})

testthat::test_that("test that the function fails when download of jwks fails", {

  # public key to to be used as signature for JWT
  key <- openssl::rsa_keygen()
  pub_key <- as.list(key)$pubkey

  # test data
  test_res <- list()
  test_kid = "thisismykid"
  test_client_id = "xxx"

  # generate JWT
  token <- jose::jwt_claim(name = "Franz",
                           uid = 509,
                           aud = test_client_id,
                           iss = "https://accounts.google.com")

  jwt <- jose::jwt_encode_sig(token, key, header = list(kid = test_kid))
  test_req <- list(HTTP_AUTHORIZATION = jwt)

  # NULL is returned when download fails
  mockery::stub(sealr::is_authed_oidc_google, "download_jwks", NULL)

  res <- sealr::is_authed_oidc_google(req = test_req,
                                        res = test_res,
                                        token_location = "header",
                                        client_id = test_client_id)
  testthat::expect_false(res$is_authed)
  testthat::expect_equal(res$code, 500)
  testthat::expect_equal(res$message, "Authentication Error. Hint: jwks_uri")

})

testthat::test_that("test that the function fails if kid is not part of jwks", {

  # public key to to be used as signature for JWT
  key <- openssl::rsa_keygen()
  pub_key <- as.list(key)$pubkey

  # test data
  test_res <- list()
  test_kid = "thisismykid"
  test_client_id = "xxx"

  # generate JWT
  token <- jose::jwt_claim(name = "Franz",
                           uid = 509,
                           aud = test_client_id,
                           iss = "https://accounts.google.com")

  jwt <- jose::jwt_encode_sig(token, key, header = list(kid = test_kid))
  test_req <- list(HTTP_AUTHORIZATION = jwt)

  # NULL is returned when download fails
  mockery::stub(sealr::is_authed_oidc_google, "download_jwks", data.frame(kid = c("1", "2", "3")))

  res <- sealr::is_authed_oidc_google(req = test_req,
                                        res = test_res,
                                        token_location = "header",
                                        client_id = test_client_id)
  testthat::expect_false(res$is_authed)
  testthat::expect_equal(res$code, 500)
  testthat::expect_equal(res$message, "Authentication Error. Hint: jwks_uri")

})

