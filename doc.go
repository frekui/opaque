// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

/*
Package opaque contains an implementation of OPAQUE, a password authenticated
key exchange protocol described. OPAQUE is described in [1] and [2].

OPAQUE can be split into two parts, a password registration protocol and a
protocol for authentication once the user's password has been registered. It's
assumed that the password registration protocol runs over an authentication
connection (the authentication protocol does, of course, not have such an
assumption). The client initiates the password registration protocol by calling
PwRegInit. Similarly, the authentication protocol is initiated by the client
calling AuthInit.

If the authentication protocol finishes successfully a newly generated random
secret is shared between the client and server. The secret can be used to
protect any future communication between the peers.

A number of structs with messages for the two protocols (AuthMsg1, AuthMsg2,
AuthMsg3, PwRegMsg1, PwRegMsg2, PwRegMsg3) are defined in this package. It's up
to the user of the package to serialize and deserialize these structs and send
them from the client/server to the peer on the other end. In the example server
and client (cmd/server and cmd/client) the messages are serialized using JSON,
which is simple and works but isn't the most efficient option.

IMPORTANT NOTE: This code has been written for educational purposes only. No
experts in cryptography or IT security have reviewed it. Do not use it for
anything important.

[1] https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00

[2] Jarecki, S., Krawczyk, H., and J. Xu, "OPAQUE: An Asymmetric PAKE Protocol
Secure Against Pre-Computation Attacks", Eurocrypt , 2018. (Full version
available at https://eprint.iacr.org/2018/163.pdf)
*/
package opaque
