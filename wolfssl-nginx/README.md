wolfssl-nginx
=============

Build WolfSSL:

```
./configure --prefix=/opt/wolfssl \
        --enable-mlkem            \
        --enable-kyber            \
        --enable-dilithium        \
        --enable-quic             \
        --enable-nginx            \
        --enable-opensslall       \
        --enable-opensslextra     \
        --enable-all-crypto       \
        --enable-ipv6
```

Use nginx-1.24.0 so you can cleanly apply the patch
from
https://github.com/wolfSSL/wolfssl-nginx/blob/master/nginx-1.24.0-wolfssl.patch,
then configure nginx with

```
    --with-wolfssl=/opt/wolfssl                                    \
    --with-ld-opt="-L/opt/wolfssl/lib -Wl,-rpath,/opt/wolfssl/lib" \
    --with-cc-opt="-I/opt/wolfssl/include"
```

Otherwise, follow this guide:
https://www.linode.com/docs/guides/post-quantum-encryption-nginx-ubuntu2404/
