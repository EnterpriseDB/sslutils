DROP FUNCTION openssl_csr_to_crt(text, text, text);
DROP FUNCTION openssl_rsa_generate_crl(text, text);
DROP FUNCTION openssl_revoke_certificate(text, text);

CREATE OR REPLACE FUNCTION openssl_csr_to_crt(text, text, text, integer DEFAULT NULL)
RETURNS text
AS '$libdir/sslutils', 'openssl_csr_to_crt'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION openssl_csr_to_crt(text, text, text, integer DEFAULT NULL) IS 'Generates the CA/self signed certificate.
-- Parameters:
-- param1 : csr or certificate signing request 
-- param2 : Path to CA certificate OR NULL If CA self signed certificate is required.
-- param3 : Path to CA private key OR Path to self private key, If param2 is NULL.
-- param4 : The validity days of generated certificate.';

CREATE OR REPLACE FUNCTION openssl_rsa_generate_crl(text, text, integer DEFAULT NULL)
RETURNS text
AS '$libdir/sslutils', 'openssl_rsa_generate_crl'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION openssl_rsa_generate_crl(text, text, integer DEFAULT NULL) IS 'Generates the Certificate Revocation List (CRL).
-- Parameters:
-- param1 : Path to CA certificate.
-- param2 : Path to CA private key.
-- param3 : The validity days of generated CRL.';

CREATE OR REPLACE FUNCTION openssl_revoke_certificate(text, text, integer DEFAULT NULL)
RETURNS text
AS '$libdir/sslutils', 'openssl_revoke_certificate'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION openssl_revoke_certificate(text, text, integer DEFAULT NULL) IS 'Revoke Certificate and add to Certificate Revocation List (CRL).
-- Parameters:
-- param1 : Path to client certificate to be revoked.
-- param2 : CRL file name specified in postgres config file.
-- param3 : The validity days of revoked certificate.';
