
# Security


When developing a plumber API, some considerations regarding security must be made.

Many things are already covered in the excellent [Security](https://www.rplumber.io/docs/security.html) section of the plumber docs, so we mostly link to the respective subsections and add specifics related to authentication/authorization.

## HTTPS


Using HTTPS instead of the insecure HTTP is crucial when working with authentication. The data exchanged between your plumber API and the (frontend) application is *highly* sensitive. If you don't use https, those data will be sent across the network unencrypted and attackers could easily steal access tokens not only for your plumber API but also tokens exchanged as part of the OAuth dance used for authenticating using Google.

Read more about why using HTTPS is critical in the [plumber docs](https://www.rplumber.io/docs/security.html#https). There you also learn more about how you can enable HTTPS for your plumber API. 

**All our examples assume that you use HTTPS.**


## Cookies and CSRF 

## Local storage and XSS
