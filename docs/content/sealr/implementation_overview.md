---
title: "Implementation Overview"
output: 
  md_document:
    preserve_yaml: true
weight: 3
---

authenticate
------------

*sealr*’s main function is the `authenticate` function. It is supposed
to be used within a plumber filter. `authenticate` takes a `is_authed_*`
function (see below) as input and depending on the output of this
“checker” function, takes action:

-   if the request is authenticated / authorized, it forwards to the
    next plumber handler using `plumber::forward`.
-   if the request is not authenticated / authorized, it `return`s to
    the user, passing forward HTTP status code, description and message
    from the output of the `is_authed_` function. Most often, this will
    be a “401 - Authentication failed.” error.

By accepting a function object as argument, `authenticate` is quite
flexible: You can even pass your own `is_authed` function. See the
examples section of `?sealr::authenticate` for a simple example.

is\_authed functions
--------------------

The functions starting with `is_authed` provide the actual
implementations of the different authentication / authorization
strategies that *sealr* aims to provide. Currently implemented are:

-   `is_authed_jwt`: implements JSON Web Token verification and
    checking.
-   `is_authed_oauth2_google`: implements Google’s OpenID Connect (which
    is based on OAuth2.0)

`is_authed_*` functions return a list with the following elements:

-   `is_authed`: TRUE or FALSE. Result of the check whether the request
    is authenticated / authorized.
-   `status`: character. Optional (typically only set if `is_authed` is
    FALSE). Short description of HTTP status code.
-   `code`: integer. Optional (typically only set if `is_authed` is
    FALSE). HTTP status code.
-   `message`: character. Optional (typically only set if `is_authed` is
    FALSE). Longer description.

Usage of the `is_authed` functions is not restricted to plumber filters.
For example, you can use an `is_authed` function at the top of an
endpoint to restrict access to certain endpoints or use different
authorization “levels” for different endpoints. This is particularly
relevant if you have more than two “levels” of authorization (see the
[claims
example](https://jandix.github.io/sealr/docs/jwt/jwt_claims_example/)).
