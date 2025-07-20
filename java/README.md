Java PQC PoC
============

This directory contains a client and a server PoC
using [Bouncy Castle](https://bouncycastle.org/).  The
`Makefile` assumes you have the following Bouncy
Castle jars in the directory `./cp/`:

* bcpkix-jdk18on-1.81.jar
* bcpqc-addon-fips-1.0.1.jar
* bcprov-jdk18on-1.81.jar
* bctls-jdk18on-1.81.jar
* bcutil-jdk18on-1.81.jar

Unfortunately, I was not able to find a way to have
[the server report the negotiated
group](https://github.com/bcgit/bc-java/issues/2117).
If you know how to do that... PR welcome!

For the server, you will want to have an x509 cert.
You can generate a self-signed cert via:

```
openssl req -x509 -newkey rsa:2048 -keyout key.pem  \
        -out cert.pem -sha256 -days 90 -nodes       \
        -subj "/CN=$(hostname)"
```
