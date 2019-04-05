---
title: "General Idea"
output: 
  md_document:
    preserve_yaml: true
always_allow_html: yes

weight: 2
---

Plumber filters for authentication / authorization
--------------------------------------------------

The primary logic of *sealr* is based on plumber filters (although you
can use sealr functionality without filters as well by using the
`is_authed` functions directly, see below). “Plumber filters can be used
to define a “pipeline” for handling incoming requests" ([Plumber
docs](https://www.rplumber.io/docs/routing-and-input.html#filters)).

So if your plumber API receives a request, the request will first be
routed through the different filters before it “arrives” at its
destination endpoint.

The idea of *sealr* is to use a filter for authentication. If a request
is not properly authenticated / authorized, *sealr* will immediately
return a “401 - Authentication failed.” error from the filter to the
user. In this way, an unauthenticated / unauthorized request will not
“reach” its destination endpoint.