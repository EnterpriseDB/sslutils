DO $sslutils$
DECLARE
    owner_role pg_catalog.pg_roles%ROWTYPE;
    signature text;
BEGIN
    SELECT * INTO owner_role FROM pg_catalog.pg_roles
        WHERE rolname = 'sslutils_owner';
    IF NOT FOUND THEN
        CREATE ROLE sslutils_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            INHERIT NOREPLICATION;
    ELSE
        IF owner_role.rolcanlogin OR owner_role.rolsuper
            OR owner_role.rolcreatedb OR owner_role.rolcreaterole
            OR owner_role.rolreplication OR owner_role.rolbypassrls
            OR NOT owner_role.rolinherit
            OR EXISTS (SELECT FROM pg_catalog.pg_auth_members
                       WHERE roleid = owner_role.oid)
            OR EXISTS (SELECT FROM pg_catalog.pg_auth_members AS membership
                       JOIN pg_catalog.pg_roles AS granted
                         ON granted.oid = membership.roleid
                       WHERE membership.member = owner_role.oid
                         AND granted.rolname NOT IN
                             ('pg_read_server_files', 'pg_write_server_files')) THEN
            RAISE EXCEPTION 'sslutils_owner must be an INHERIT, nonadministrative NOLOGIN role with no members and only file-role memberships';
        END IF;
    END IF;

    IF pg_catalog.current_setting('server_version_num')::integer >= 110000 THEN
        GRANT pg_read_server_files, pg_write_server_files TO sslutils_owner;
    END IF;

    FOREACH signature IN ARRAY ARRAY[
        'openssl_rsa_generate_key(integer)',
        'openssl_rsa_key_to_csr(text,text,text,text,text,text,text)',
        'openssl_csr_to_crt(text,text,text,integer)',
        'openssl_rsa_generate_crl(text,text,integer)',
        'openssl_is_crt_expire_on(text,timestamptz)',
        'openssl_revoke_certificate(text,text,integer)',
        'openssl_get_crt_expiry_date(text)'
    ]
    LOOP
        EXECUTE 'ALTER FUNCTION ' || signature ||
            ' SECURITY DEFINER VOLATILE SET search_path = pg_catalog, pg_temp';
        EXECUTE 'REVOKE ALL ON FUNCTION ' || signature || ' FROM PUBLIC';
        EXECUTE 'ALTER FUNCTION ' || signature || ' OWNER TO sslutils_owner';
        IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pem_agent') THEN
            EXECUTE 'GRANT EXECUTE ON FUNCTION ' || signature || ' TO pem_agent';
        END IF;
    END LOOP;
END
$sslutils$;
