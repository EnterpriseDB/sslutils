CREATE OR REPLACE FUNCTION sslutils_version()
RETURNS text
AS 'MODULE_PATHNAME', 'sslutils_version'
LANGUAGE C IMMUTABLE;
COMMENT ON FUNCTION sslutils_version() IS 'Returns the current version of sslutils';

