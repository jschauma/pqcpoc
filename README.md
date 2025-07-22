PQC PoC
=======

This repository contains proof of concept code of
post-quantum cryptography implementations using TLS
1.3 Hybrid Key Exchange with `X25519MLKEM768`.

The server implementations can be tested either with
your browser (as of July 2025 using Chrome or Firefox)
or via OpenSSL (either >= 3.5 or using the
[OpenQuatumSafe](https://openquantumsafe.org/)
provider):

```
$ printf "GET / HTTP/1.0\r\n\r\n" | \
        openssl s_client -ign_eof -groups X25519MLKEM768 -connect <server>:<port>
[...]
Negotiated TLS1.3 group: X25519MLKEM768
```

If your `curl` is linked against a PQC enabled TLS
library, then you can also do this:

```
$ curl -v -s -o /dev/null --curves X25519:X25519MLKEM768 https://<server>
```

Sample services
---------------

Sample PoC endpoints that I've currently set up are:

* https://boringssl-nginx.pqc.dotwtf.wtf
* https://golang.pqc.dotwtf.wtf
* https://java-bc.pqc.dotwtf.wtf
* https://openssl-nginx.pqc.dotwtf.wtf
* https://openssl-oqs-apache.pqc.dotwtf.wtf
* https://wolfssl-nginx.pqc.dotwtf.wtf

See [this blog post](https://www.netmeister.org/blog/pqc-pocs.html) for more information.

