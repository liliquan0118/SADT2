# 1.https://github.com/openssl/openssl/issues/10599
openssl 1.1.1-pre8 accepts a certificate with version 1 and extension fields
# 2.https://bugzilla.mozilla.org/show_bug.cgi?id=1603034
NSS accepts a version-1 certificate with extension fields
# 3.https://github.com/wolfSSL/wolfssl/issues/2680
wolfssl4.2.0 accepts a certificate whose issuer not matching the subject of CA certificate
# 4.https://gitlab.com/gnutls/gnutls/-/issues/885
gnutls can't check certificate issuer correctly according to RFC5280
# 5. https://gitlab.com/gnutls/gnutls/issues/864
GnuTLS3.6.7.1 cannot process validity field according to RFC5280
# 6.https://bugzilla.mozilla.org/show_bug.cgi?id=1599331
NSS UTCTime parser should reject short fields (e.g., should require the seconds digits).
# 7.https://gitlab.com/gnutls/gnutls/issues/870
Gnutls3.6.7 accepts a certificate whose notbefore field is a non-digits string while openssl rejects such certificates
# 8.https://github.com/wolfSSL/wolfssl/issues/2657
wolfssl 4.0.0 accepts a certificate with an invalid time format
# 9.https://github.com/ARMmbed/mbedtls/issues/2954
mbedtls2.16.3 accepts invalid certificate whose key identifier field of the authority key identifier extension is not the same as subject key identifier in issuer
# 10.https://github.com/wolfSSL/wolfssl/issues/2659
wolfssl-4.0.0 accepts a certificate with authority key identifier extension field that do not match issuer 
# 11.https://gitlab.com/gnutls/gnutls/-/issues/886
gnutls can't check object identifier value correctly
# 12.https://gitlab.com/gnutls/gnutls/-/issues/887
gnutls accepts certificates including two instance of a particular extension
# 13.https://github.com/openssl/openssl/issues/10686
openssl accepts certificates including two instance of a particular extension
