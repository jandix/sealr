context("check claims function")

testthat::test_that("test that check_claim can check a simple atomic value", {
  token <- list(aud = 2)
  testthat::expect_true(sealr::check_claim("aud", 2, token))
})

testthat::test_that("test that check_claim returns true on a simple atomic value", {
  token <- list(aud = "hello")
  testthat::expect_true(sealr::check_claim("aud", "hello", token))
})


testthat::test_that("test that check_claim returns false on a simple atomic value", {
  token <- list(aud = 12)
  testthat::expect_false(sealr::check_claim("aud", 13, token))
})

testthat::test_that("test that check_claim returns false on a simple atomic value", {
  token <- list(aud = "hello")
  testthat::expect_false(sealr::check_claim("aud", "hello world", token))
})

testthat::test_that("test that check_claim returns true on list", {
  token <- list(aud = list(a = "foo"))
  testthat::expect_true(sealr::check_claim("aud", list(a = "foo"), token))
})

testthat::test_that("test that check_claim returns true on 2 length list", {
  token <- list(aud = list(a = "foo", b = "bar"))
  testthat::expect_true(sealr::check_claim("aud", list(a = "foo", b = "bar"), token))
})

testthat::test_that("test that check_claim returns true on 2 length list, indifferent to order", {
  token <- list(aud = list(b = "bar", a = "foo"))
  testthat::expect_true(sealr::check_claim("aud", list(a = "foo", b = "bar"), token))
})

testthat::test_that("test that check_claim returns true on 2 length list, indifferent to order", {
  token <- list(aud = list(b = "bar", a = "foo"))
  testthat::expect_true(sealr::check_claim("aud", list(a = "foo", b = "bar"), token))
})

testthat::test_that("test that check_claim returns true on NULL", {
  token <- list(aud = NULL)
  testthat::expect_true(sealr::check_claim("aud", NULL, token))
})

testthat::test_that("test that check_all_claims returns True with one correct claim", {
  token <- list(aud = "hello")
  claims <- list(aud = "hello")
  testthat::expect_true(sealr::check_all_claims(token, claims))
})

testthat::test_that("test that check_all_claims returns True with two correct claims", {
  token <- list(aud = "hello", iss = "company")
  claims <- list(aud = "hello", iss = "company")

  testthat::expect_true(sealr::check_all_claims(token, claims))
})

testthat::test_that("test that check_all_claims returns False with one false claim", {
  token <- list(aud = "hello", iss = "company")
  claims <- list(aud = "hello", iss = "company 2")
  testthat::expect_false(sealr::check_all_claims(token, claims))
})
