use strict;
use warnings;

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;
use File::Path qw(make_path);

my $node = PostgreSQL::Test::Cluster->new('security');
$node->init;
my $datadir = $node->data_dir;
make_path("$datadir/crls", "$datadir/crls-other", "$datadir-other");
$node->append_conf('postgresql.conf',
    "sslutils.revoke_certificate_crl_paths = '\"$datadir/crls\"'\n");
$node->start;
$node->safe_psql('postgres', q{
    CREATE ROLE pem_agent LOGIN;
    CREATE ROLE unrelated;
    CREATE EXTENSION sslutils;
});

sub agent_sql
{
    my ($sql) = @_;
    return $node->safe_psql('postgres', "SET ROLE pem_agent; $sql");
}

sub denied
{
    my ($sql, $error, $description, $role) = @_;
    $role //= 'pem_agent';
    my ($stdout, $stderr);
    my $status = $node->psql('postgres', "SET ROLE $role; $sql",
        stdout => \$stdout, stderr => \$stderr);
    ok($status != 0 && $stderr =~ $error, $description)
        or diag("status=$status stdout=$stdout stderr=$stderr");
}

is($node->safe_psql('postgres', q{
    SELECT count(*) FROM pg_proc
    WHERE pronamespace = 'public'::regnamespace
      AND proname LIKE 'openssl_%'
      AND proowner = 'sslutils_owner'::regrole
      AND prosecdef AND provolatile = 'v'
      AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']
      AND has_function_privilege('pem_agent', oid, 'EXECUTE')
      AND NOT has_function_privilege('unrelated', oid, 'EXECUTE')
}), '7', 'all seven functions have restricted definer ownership and execution');

is($node->safe_psql('postgres', q{
    SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolcreaterole
        AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls
    FROM pg_roles WHERE rolname = 'sslutils_owner'
}), 't', 'owner is an unprivileged NOLOGIN role');
is($node->safe_psql('postgres', q{
    SELECT pg_has_role('sslutils_owner', 'pg_read_server_files', 'USAGE')
       AND pg_has_role('sslutils_owner', 'pg_write_server_files', 'USAGE')
       AND NOT pg_has_role('pem_agent', 'sslutils_owner', 'MEMBER')
       AND NOT pg_has_role('pem_agent', 'pg_read_server_files', 'MEMBER')
       AND NOT pg_has_role('pem_agent', 'pg_write_server_files', 'MEMBER')
}), 't', 'only the owner holds file roles');

my $key = agent_sql('SELECT openssl_rsa_generate_key(2048)');
like($key, qr/BEGIN PRIVATE KEY/, 'agent generates a key');
append_to_file("$datadir/ca_key.key", "$key\n");
my $csr = agent_sql(qq{
    SELECT openssl_rsa_key_to_csr(\$key\$$key\$key\$,
        'test', 'US', 'state', 'city', 'unit', 'test\@example.invalid')
});
like($csr, qr/BEGIN CERTIFICATE REQUEST/, 'agent generates a CSR');
my $cert = agent_sql(qq{
    SELECT openssl_csr_to_crt(\$csr\$$csr\$csr\$, NULL, 'ca_key.key', 365)
});
like($cert, qr/BEGIN CERTIFICATE/, 'agent signs a self-signed certificate');
append_to_file("$datadir/ca_certificate.crt", "$cert\n");
append_to_file("$datadir-other/outside.crt", "$cert\n");
append_to_file("$datadir/crls-other/outside.crl", "unchanged\n");
like(agent_sql(qq{
    SELECT openssl_csr_to_crt(\$csr\$$csr\$csr\$,
        'ca_certificate.crt', 'ca_key.key', 30)
}), qr/BEGIN CERTIFICATE/, 'agent signs using the CA certificate and key');
like(agent_sql(q{
    SELECT openssl_rsa_generate_crl('ca_certificate.crt', 'ca_key.key', 30)
}), qr/BEGIN X509 CRL/, 'agent generates a CRL');
like(agent_sql(q{
    SELECT openssl_get_crt_expiry_date('ca_certificate.crt')
}), qr/^\d{4}-/, 'agent reads certificate expiry');
is(agent_sql(q{
    SELECT openssl_is_crt_expire_on('ca_certificate.crt', now())
}), '1', 'agent checks certificate expiry');
like(agent_sql(qq{
    SELECT openssl_revoke_certificate(\$cert\$$cert\$cert\$,
        '$datadir/crls/revoked.crl', 30)
}), qr/BEGIN X509 CRL/, 'agent revokes a certificate and writes a CRL');
ok(-s "$datadir/crls/revoked.crl", 'revocation persisted its output');

for my $file ('ca_certificate.crt', 'ca_key.key', 'pg_hba.conf')
{
    denied("SELECT pg_read_file('$file')", qr/permission denied/,
        "agent cannot read $file directly");
    denied(qq{
        CREATE TEMP TABLE copied(line text);
        COPY copied FROM '$datadir/$file'
    }, qr/pg_read_server_files/, "agent cannot COPY from $file");
}
denied(q{COPY (SELECT 'invalid') TO '/tmp/sslutils-forbidden-output'},
    qr/pg_write_server_files/, 'agent cannot write server files directly');
{
    my ($stdout, $stderr);
    my $status = $node->psql('postgres', 'SET ROLE sslutils_owner',
        extra_params => ['-U', 'pem_agent'],
        stdout => \$stdout, stderr => \$stderr);
    ok($status != 0 && $stderr =~ /permission denied/,
        'agent session cannot assume the function owner')
        or diag("status=$status stdout=$stdout stderr=$stderr");
}
denied(q{SELECT openssl_rsa_generate_key(2048)}, qr/permission denied/,
    'unrelated roles cannot execute the functions', 'unrelated');
denied(qq{SELECT openssl_get_crt_expiry_date('$datadir-other/outside.crt')},
    qr/PATH_NOT_IN_PGDATA/, 'certificate directory prefix bypass is rejected');
denied(q{SELECT openssl_get_crt_expiry_date('pg_hba.conf')},
    qr/PEM_read_X509/, 'certificate API does not expose configuration file contents');
denied(q{
    SELECT openssl_get_crt_expiry_date('ca_certificate.crt');
    SET sslutils.revoke_certificate_crl_paths = '/tmp'
},
    qr/cannot be changed now|permission denied/,
    'agent cannot widen the CRL output allowlist');
denied(qq{
    SET sslutils.revoke_certificate_crl_paths = '/tmp';
    SELECT openssl_revoke_certificate(\$cert\$$cert\$cert\$,
        '$datadir/crls-other/escape.crl', 30)
}, qr/CRL file path not in|cannot be changed now|permission denied/,
    'a placeholder setting cannot bypass the allowlist before module load');

for my $path ("$datadir/crls-other/outside.crl",
              "$datadir/crls/../crls-other/new.crl")
{
    denied(qq{
        SELECT openssl_revoke_certificate(\$cert\$$cert\$cert\$, '$path', 30)
    }, qr/CRL file path not in/, 'CRL directory escape is rejected');
}
SKIP:
{
    skip 'symlink checks are Unix-specific', 2 if $windows_os;
    symlink("$datadir/crls-other/outside.crl", "$datadir/crls/link.crl")
        or die "symlink: $!";
    denied(qq{
        SELECT openssl_revoke_certificate(\$cert\$$cert\$cert\$,
            '$datadir/crls/link.crl', 30)
    }, qr/CRL file path not in/, 'CRL symlink escape is rejected');
    symlink("$datadir/crls-other/missing.crl", "$datadir/crls/dangling.crl")
        or die "symlink: $!";
    denied(qq{
        SELECT openssl_revoke_certificate(\$cert\$$cert\$cert\$,
            '$datadir/crls/dangling.crl', 30)
    }, qr/CRL file path not in/, 'dangling CRL symlink escape is rejected');
}

$node->safe_psql('postgres', q{
    CREATE DATABASE upgrade_test;
    CREATE DATABASE schema_test;
    CREATE DATABASE legacy_test;
});
$node->safe_psql('upgrade_test', q{
    CREATE EXTENSION sslutils VERSION '1.4.1';
    GRANT EXECUTE ON FUNCTION openssl_get_crt_expiry_date(text) TO unrelated;
    GRANT pg_read_server_files, pg_write_server_files TO pem_agent;
    ALTER EXTENSION sslutils UPDATE TO '1.4.2';
});
is($node->safe_psql('upgrade_test', q{
    SELECT extversion FROM pg_extension WHERE extname = 'sslutils'
}), '1.4.2', 'existing extension upgrades to 1.4.2');
is($node->safe_psql('upgrade_test', q{
    SELECT count(*) FROM pg_proc
    WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'openssl_%'
      AND prosecdef AND proowner = 'sslutils_owner'::regrole
      AND has_function_privilege('pem_agent', oid, 'EXECUTE')
}), '7', 'upgrade converts all seven functions and grants PEM access');
is($node->safe_psql('upgrade_test', q{
    SELECT has_function_privilege('unrelated',
        'openssl_get_crt_expiry_date(text)', 'EXECUTE')
       AND NOT has_function_privilege('unrelated',
        'openssl_rsa_generate_key(integer)', 'EXECUTE')
}), 't', 'upgrade preserves explicit grants but revokes public execution');
$node->safe_psql('upgrade_test', q{
    REVOKE pg_read_server_files, pg_write_server_files FROM pem_agent;
});
like($node->safe_psql('upgrade_test', q{
    SET ROLE pem_agent;
    SELECT openssl_get_crt_expiry_date('ca_certificate.crt')
}), qr/^\d{4}-/, 'upgraded function works after PEM revokes file roles');

$node->safe_psql('schema_test', q{
    CREATE SCHEMA certificates;
    CREATE EXTENSION sslutils SCHEMA certificates;
    GRANT USAGE ON SCHEMA certificates TO pem_agent;
});
like($node->safe_psql('schema_test', q{
    SET ROLE pem_agent;
    SELECT certificates.openssl_get_crt_expiry_date('ca_certificate.crt')
}), qr/^\d{4}-/, 'definer functions work in a non-public schema');

my ($sharedir) = PostgreSQL::Test::Utils::run_command(['pg_config', '--sharedir']);
chomp $sharedir;
$node->safe_psql('legacy_test', slurp_file("$sharedir/extension/sslutils.sql"));
is($node->safe_psql('legacy_test', q{
    SELECT count(*) FROM pg_proc
    WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'openssl_%'
      AND prosecdef AND proowner = 'sslutils_owner'::regrole
}), '7', 'legacy installation applies the same ownership policy');

$node->safe_psql('postgres', q{
    DROP DATABASE upgrade_test;
    DROP DATABASE schema_test;
    DROP DATABASE legacy_test;
    DROP EXTENSION sslutils;
    DROP ROLE pem_agent;
    ALTER ROLE sslutils_owner LOGIN;
});
my ($stdout, $stderr);
isnt($node->psql('postgres', 'CREATE EXTENSION sslutils',
    stdout => \$stdout, stderr => \$stderr), 0,
    'installation refuses an unsafe pre-existing owner');
like($stderr, qr/sslutils_owner must be/, 'unsafe owner failure is explicit');
$node->safe_psql('postgres', q{
    ALTER ROLE sslutils_owner NOLOGIN;
    GRANT sslutils_owner TO unrelated;
});
isnt($node->psql('postgres', 'CREATE EXTENSION sslutils',
    stdout => \$stdout, stderr => \$stderr), 0,
    'installation refuses an owner that agents could assume');
$node->safe_psql('postgres', q{
    REVOKE sslutils_owner FROM unrelated;
    GRANT pg_execute_server_program TO sslutils_owner;
});
isnt($node->psql('postgres', 'CREATE EXTENSION sslutils',
    stdout => \$stdout, stderr => \$stderr), 0,
    'installation refuses an owner with unrelated role privileges');
$node->safe_psql('postgres', q{
    REVOKE pg_execute_server_program FROM sslutils_owner;
    CREATE EXTENSION sslutils;
    CREATE ROLE pem_agent LOGIN;
});
$node->safe_psql('postgres', slurp_file("$sharedir/extension/sslutils-pemagent.sql"));
like(agent_sql(q{SELECT openssl_rsa_generate_key(2048)}),
    qr/BEGIN PRIVATE KEY/, 'grant script supports agents created after installation');

$node->stop;
done_testing();
