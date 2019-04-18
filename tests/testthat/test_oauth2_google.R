testthat::context("Test OAuth2 Google Strategy")

# TEST MISSING INPUTS ------------------------------------------------------------------------------------

testthat::test_that("test that the function requires request object", {
  testthat::expect_error(sealr::is_authed_oauth2_google(res = list(), client_id = "xxx"),
                         regexp = "Please pass the request object.")
})

testthat::test_that("test that the function requires response object", {
  testthat::expect_error(sealr::is_authed_oauth2_google(req = list(), client_id = "xxx"),
                         regexp = "Please pass the response object.")
})

testthat::test_that("test that the function requires token_location", {
  testthat::expect_error(sealr::is_authed_oauth2_google(req = list(), res = list(),
                                                        client_id = "xxx"),
                         regexp = "Please specify a token location.")
})

testthat::test_that("test that the function requires client_id", {
  testthat::expect_error(sealr::is_authed_oauth2_google(req = list(), res = list(), token_location = "header"),
                         regexp = "Please pass the Google client id.")
})

# TEST FUNCTION ------------------------------------------------------------------------------------------

testthat::test_that("test that the function requires HTTP_AUTHORIZATION header if token_location is 'header'.", {
  # test data
  test_req <- list()
  test_res <- list()
  client_id <- "xxx"

  res <- sealr::is_authed_oauth2_google(req = test_req,
                                        res = test_res,
                                        token_location = "header",
                                        client_id = test_client_id)
  testthat::expect_false(res$is_authed)
})

testthat::test_that("test that the function requires valid HTTP_AUTHORIZATION", {
  # test data
  test_req <- list(HTTP_AUTHORIZATION = "xxx.xxx.xxx")
  test_res <- list()
  client_id <- "xxx"

  res <- sealr::is_authed_oauth2_google(req = test_req,
                                        res = test_res,
                                        token_location = "header",
                                        client_id = test_client_id)
  testthat::expect_false(res$is_authed)
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

  res <- sealr::is_authed_oauth2_google(req = test_req,
                                        res = test_res,
                                        token_location = "header",
                                        client_id = test_client_id)
  testthat::expect_false(res$is_authed)
})


testthat::test_that("test that the function requires valid HTTP_AUTHORIZATION that matches google key", {

  # generate JWT
  # test data
  key <- openssl::rsa_keygen()
  pub_key <- as.list(key)$pubkey
  token <- jose::jwt_claim(name = "Franz",
                           uid = 509)
  jwt <- jose::jwt_encode_sig(token, key)


  jwt_split_up <- jwt_split(jwt)
  jwt_split_up$header$kid <- "thisismykid"

  # decode and get kid
  token <- jose::jwt_encode_sig(token, key)

  # download public key file
  jwks_uri <- "https://www.googleapis.com/oauth2/v3/certs"
  response <- httr::GET(jwks_uri)

  # TURN INTO TESTTHAT
  if (httr::http_error(response)) {
    return(FALSE)
  }
  jwks <- jsonlite::fromJSON(httr::content(response, type = "text", encoding = "UTF-8"))$keys
  jwks$kid <-
  mockery::stub(sealr::is_authed_oauth2_google, "jsonlite::fromJSON",
                )
  # we need to mock the fromJSON method as this is where the dataframe is regturned

  # match kid
  jwks
  index <- which(jwks$kid == jwt$header$kid)



  test_req <- list(HTTP_AUTHORIZATION = jwt)
  test_res <- list()
  client_id <- "xxx"

  res <- sealr::is_authed_oauth2_google(req = test_req,
                                        res = test_res,
                                        token_location = "header",
                                        client_id = test_client_id)
  testthat::expect_false(res$is_authed)
})
