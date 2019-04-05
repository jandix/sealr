---
output: 
  md_document:
    preserve_yaml: true
title: sealr
weight: 1
---

<!-- README.md is generated from README.Rmd. Please edit that file -->

[![Build
Status](https://travis-ci.org/jandix/sealr.svg?branch=master)](https://travis-ci.org/jandix/sealr)

The goal of sealr is to provide multiple authentication and
authorization strategies for [plumber](https://www.rplumber.io/) by
using
[filters](https://www.rplumber.io/docs/routing-and-input.html#filters).
In doing so, we hope to make best practices in authentication easy to
implement for the R community. The package is inspired by the amazing
[passport.js](http://www.passportjs.org/) library for Node.js.

Disclaimer
----------

⚠️ We are currently looking for security experts to help us develop this
project / review our code. That being said, while we try to thouroughly
understand the concepts behind a strategy before we implement it in
*sealr*, **we are not experts** in security. Please make sure you
understand the risks and possible attack vectors when using *sealr* -
especially in production environments. ⚠️

Installation
------------

Currently, the package is under development. Please feel free to
contribute to the package. You can install and use the package using
`devtools`.

    devtools::install_github("jandix/sealr")

Contribute
----------

We are still at the very beginning of the package and we welcome any
support and contribution. Comment on an existing issue or file a new one
on [GitHub](https://github.com/jandix/sealr/issues).

Testing
-------

You can use curl for testing purposes. Unfortunately, curl quickly gets
quite complicated if you want to add a body, parameters and unique
headers. Therefore, we recommend to use
[Postman](https://www.getpostman.com/) for larger, more complicated
projects.

Examples
--------

We provide some simple sample implementations for different strategies
and use cases. You can find them on the subpages of the different
strategies in the navigation bar on the left.

Warranity Notice
----------------

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
