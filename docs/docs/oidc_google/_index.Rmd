---
output: 
  md_document:
    preserve_yaml: true
title: Google - OpenID Connect
weight: 3
---

The Google OAuth2 strategy allows you to use Google’s OpenID Connect
interface to authenticate and authorize your users. A detailed
introduction and best practices can be found
[here](https://developers.google.com/identity/protocols/OpenIDConnect).
The interface uses JWTs. Hence, the process can be considered stateless.
Addtionally, the user tokens can be used to access Google APIs.
