CREATE OR REPLACE FUNCTION openssl_is_crt_expire_on(text, timestamptz)
RETURNS integer
AS 'MODULE_PATHNAME', 'openssl_is_crt_expire_on'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION openssl_is_crt_expire_on(text, timestamptz) IS 'Compare certificate expiry on given time.
-- Parameters:
-- param1 : Path to certificate.
-- param2 : time to compare with end date';

CREATE OR REPLACE FUNCTION openssl_revoke_certificate(text, text, text, text, text)
RETURNS text
AS 'MODULE_PATHNAME', 'openssl_revoke_certificate'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION openssl_revoke_certificate(text, text, text, text, text) IS 'Revoke Certificate and add to Certificate Revocation List (CRL).
-- Parameters:
-- param1 : Path to client certificate to be revoked.
-- param2 : Path to CA certificate.
-- param3 : Path to CA private key.
-- param4 : Path to database file which contains serial number of all revoked certificates.
-- param5 : Path to new CRL file to be generated.';

CREATE OR REPLACE FUNCTION openssl_get_crt_expiry_date(text)
RETURNS timestamptz
AS 'MODULE_PATHNAME', 'openssl_get_crt_expiry_date'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION openssl_get_crt_expiry_date(text) IS 'Return the expiry date of the given certificate.
-- Parameters:
-- param1 : Path to certificate.';

