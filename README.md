# OPAQUE in Go

[![GoDoc](https://godoc.org/github.com/frekui/opaque?status.png)](https://godoc.org/github.com/frekui/opaque)
[![Build Status](https://travis-ci.com/frekui/opaque.svg?branch=master)](https://travis-ci.com/frekui/opaque)

This repo contains a Go implementation of OPAQUE, a password authenticated key
exchange protocol described in [1] and [2].

**Important note**: This code has been written for educational purposes only. No
experts in cryptography or IT security have reviewed it. Do not use it for
anything important.

## Installation

`go get -u github.com/frekui/opaque`

## Documentation

https://godoc.org/github.com/frekui/opaque

## Testing

`./run-tests.sh`

## Examples

The repo contains a sample [client](cmd/client/main.go) and
[server](cmd/server/main.go) that authenticates each other using package opaque.

## License

Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com. Use of this source code
is governed by the BSD-style license that can be found in the [LICENSE](LICENSE)
file.

## References

[1] https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00

[2] Jarecki, S., Krawczyk, H., and J. Xu, "OPAQUE: An Asymmetric PAKE Protocol
Secure Against Pre-Computation Attacks", Eurocrypt , 2018. (Full version
available at https://eprint.iacr.org/2018/163.pdf)
