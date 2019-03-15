context("check claims function")

TEST_TOKEN <- list(iss = "plu",
                   user = list(
                     name = list(
                       lastname = "Smith",
                       firstname = "Alice"),
                     id = "1234"),
                   iat = 123456789,
                   admin = TRUE,
                   company = list(
                     id = 1,
                     name = "a plumber company"
                   ))

# check_claim function ---------------------------------------------------

# empty token
testthat::test_that("test that check_claim returns FALSE on empty token", {
  testthat::expect_false(sealr::check_claim("iat", 123456789, list()))
})

# different atomic types
testthat::test_that("test that check_claim can check a simple int value", {
  testthat::expect_true(sealr::check_claim("iat", 123456789, TEST_TOKEN))
})

testthat::test_that("test that check_claim returns true on a simple chr value", {
  testthat::expect_true(sealr::check_claim("iss", "plu", TEST_TOKEN))
})

testthat::test_that("test that check_claim returns true on a simple logical value", {
  testthat::expect_true(sealr::check_claim("admin", TRUE, TEST_TOKEN))
})

testthat::test_that("test that check_claim returns false on an incorrect int value", {
  testthat::expect_false(sealr::check_claim("iat", 99, TEST_TOKEN))
})

testthat::test_that("test that check_claim returns false on an incorrect chr value", {
  testthat::expect_false(sealr::check_claim("iss", "hello world", TEST_TOKEN))
})

testthat::test_that("test that check_claim returns false on an incorrect logical value", {
  testthat::expect_false(sealr::check_claim("admin", FALSE, TEST_TOKEN))
})

testthat::test_that("test that check_claim returns true on 2 length list, indifferent to order", {
  testthat::expect_true(sealr::check_claim("company", list(name = "a plumber company", id = 1), TEST_TOKEN))
})

testthat::test_that("that simple claim at first level returns TRUE", {
  test_claim_name <- "iss"
  test_claim_value <- "plu"
  testthat::expect_true(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})


testthat::test_that("that incorrect simple claim at first level returns FALSE", {
  test_claim_name <- "iss"
  test_claim_value <- "plu2"
  testthat::expect_false(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})

testthat::test_that("that simple claim at second level returns TRUE", {
  test_claim_name <- "user"
  test_claim_value <- list(id = "1234")
  testthat::expect_true(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})


testthat::test_that("that incorrect claim at second level returns FALSE", {
  test_claim_name <- "user"
  test_claim_value <- list(id = "notid")
  testthat::expect_false(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})

testthat::test_that("that correct nested claim returns TRUE", {
  test_claim_name <- "user"
  test_claim_value <- list(
    name = list(
      lastname = "Smith",
      firstname = "Alice"
    )
  )

  testthat::expect_true(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})


testthat::test_that("that correct nested claim + simple claim returns TRUE", {
  test_claim_name <- "user"
  test_claim_value <- list(
    name = list(
      lastname = "Smith",
      firstname = "Alice"
    ),
    id = "1234"
  )

  testthat::expect_true(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})

testthat::test_that("that correct nested claim + incorrect simple claim returns FALSE", {
  test_claim_name <- "user"
  test_claim_value <- list(
    name = list(
      lastname = "Smith",
      firstname = "Alice"
    ),
    id = "notid"
  )

  testthat::expect_false(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})

testthat::test_that("that correct nested claim + missing simple claim returns FALSE", {
  test_claim_name <- "user"
  test_claim_value <- list(
    name = list(
      lastname = "Smith",
      firstname = "Alice"
    ),
    notaname = "1234"
  )

  testthat::expect_false(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})

testthat::test_that("that missing nested claim in token returns FALSE.", {
  test_claim_name <- "thisclaimnamedoesnotexist"
  test_claim_value <- list(
    name = list(
      lastname = "Smith",
      firstname = "Alice"
    )
  )

  testthat::expect_false(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})

testthat::test_that("that incorrect value at base recursion level returns FALSE.", {
  test_claim_name <- "user"
  test_claim_value <- list(
    name = list(
      lastname = "Smith",
      firstname = "Smith"
    )
  )

  testthat::expect_false(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})

testthat::test_that("that non-existing claim name at base recursion level returns FALSE.", {
  test_claim_name <- "user"
  test_claim_value <- list(
    name = list(
      middlename = "Smith",
      firstname = "Alice"
    )
  )

  testthat::expect_false(sealr::check_claim(test_claim_name, test_claim_value, TEST_TOKEN))
})


# function check_all_claims --------------------------------------------------
testthat::test_that("test that check_all_claims returns False with empty token", {
  claims <- list(admin = TRUE, iat = 123456789)

  testthat::expect_false(sealr::check_all_claims(list(), claims))
})

testthat::test_that("test that check_all_claims returns False with NULL token", {
  claims <- list(admin = TRUE, iat = 123456789)

  testthat::expect_false(sealr::check_all_claims(NULL, claims))
})

testthat::test_that("test that check_all_claims returns True with one correct claim", {
  claims <- list(admin = TRUE)
  testthat::expect_true(sealr::check_all_claims(TEST_TOKEN, claims))
})

testthat::test_that("test that check_all_claims returns True with two correct claims", {
  claims <- list(admin = TRUE, iat = 123456789)

  testthat::expect_true(sealr::check_all_claims(TEST_TOKEN, claims))
})

testthat::test_that("test that check_all_claims returns True with three correct claims", {
  claims <- list(admin = TRUE, iat = 123456789,
                 user = list(name = list(lastname = "Smith", firstname = "Alice")))

  testthat::expect_true(sealr::check_all_claims(TEST_TOKEN, claims))
})

testthat::test_that("test that check_all_claims returns False with one false claim", {
  claims <- list(admin = TRUE, iat = 123456789,
                 user = list(name = list(lastname = "Smith", firstname = "Bob")))

  testthat::expect_false(sealr::check_all_claims(TEST_TOKEN, claims))
})

testthat::test_that("test that check_all_claims returns False with one claim that does not exist", {
  claims <- list(admin = TRUE, iat = 123456789, notexist = TRUE)

  testthat::expect_false(sealr::check_all_claims(TEST_TOKEN, claims))
})
