ALTER EXTENSION sslutils ADD function openssl_rsa_generate_key(integer);
ALTER EXTENSION sslutils ADD function openssl_rsa_key_to_csr(text, text, text, text, text, text, text);
ALTER EXTENSION sslutils ADD function openssl_csr_to_crt(text, text, text);
ALTER EXTENSION sslutils ADD function openssl_rsa_generate_crl(text, text);
