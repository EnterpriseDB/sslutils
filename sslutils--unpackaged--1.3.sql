ALTER EXTENSION sslutils ADD function openssl_rsa_generate_key(integer);
ALTER EXTENSION sslutils ADD function openssl_rsa_key_to_csr(text, text, text, text, text, text, text);
ALTER EXTENSION sslutils ADD function openssl_csr_to_crt(text, text, text);
ALTER EXTENSION sslutils ADD function openssl_rsa_generate_crl(text, text);

CREATE OR REPLACE FUNCTION sslutils_version()
RETURNS text
AS 'MODULE_PATHNAME', 'sslutils_version'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION sslutils_version() IS 'Returns the current version of sslutils';

CREATE OR REPLACE FUNCTION openssl_is_crt_expire_on(text, timestamptz)
RETURNS integer
AS 'MODULE_PATHNAME', 'openssl_is_crt_expire_on'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION openssl_is_crt_expire_on(text, timestamptz) IS 'Compare certificate expiry on given time.
-- Parameters:
-- param1 : Path to certificate.
-- param2 : time to compare with end date';

CREATE OR REPLACE FUNCTION openssl_revoke_certificate(text, text)
RETURNS text
AS 'MODULE_PATHNAME', 'openssl_revoke_certificate'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION openssl_revoke_certificate(text, text) IS 'Revoke Certificate and add to Certificate Revocation List (CRL).
-- Parameters:
-- param1 : Path to client certificate to be revoked.
-- param2 : CRL file name specified in postgres config file.';

CREATE OR REPLACE FUNCTION openssl_get_crt_expiry_date(text)
RETURNS timestamptz
AS 'MODULE_PATHNAME', 'openssl_get_crt_expiry_date'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION openssl_get_crt_expiry_date(text) IS 'Return the expiry date of the given certificate.
-- Parameters:
-- param1 : Path to certificate.';

