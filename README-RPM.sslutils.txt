SSLUtils
========
SSLUtils is a Postgres extension that provides SSL certicate generation
functions to Postgres, for use by the Postgres Enterprise Manager server.

The SSLUtils extension is installed by the ppas92-server-sslutils-3.0.0-1.rhel6 
package.  The SSLUtils files are installed in /usr/ppas-9.2/share/extension, 
and the libraries are installed in /usr/ppas-9.2/lib.

Before using the SSLUtils, you must create the sslutils extension.  Use the psql 
client to connect to the edb database, and issue the command:

    CREATE EXTENSION sslutils WITH VERSION "1.0";

Please note that before connecting with the psql client, you may be required 
to modify the pg_hba.conf file; the pg_hba.conf file is located in
/var/lib/ppas/9.2/data.


Functions
---------
After creating the extensions, you can use the psql command line to invoke the 
SSLUtils functions.  For example, to invoke the openssl_rsa_generate_key, connect
to the server and issue the command:

    edb=# select openssl_rsa_generate_key (4096);
                     openssl_rsa_generate_key                     
    ------------------------------------------------------------------
     -----BEGIN RSA PRIVATE KEY-----                                 +
     MIIJKQIBAAKCAgEAr6uLkjuMhMPkFyAxDrYYc5sqa/JxWWYdaGkwICS4846/qTdH+
        ...

     lkJ7GslgEHUcoLbMpSufMaX5bObwdj0J9hAtUUBqVjKxp+pcuTqeKaCGVRtc    +
     -----END RSA PRIVATE KEY-----                                   +
 
    (1 row)


SSLUtils provides the following functions:

openssl_rsa_generate_key(integer) RETURNS text

Purpose: Generates an RSA private key.
Param 1: Number of bits.
Returns: The generated key.

openssl_rsa_key_to_csr(text, text, text, text, text, text, text) RETURNS text

Purpose: Generates a certificate signing request (CSR)
Param 1: RSA key
Param 2: CN or common name e.g. agentN
Param 3: C or Country
Param 4: ST or State
Param 5: L or Location (City)
Param 6: OU or Organization Unit
Param 7: Email address
Returns: The generated CSR.

openssl_csr_to_crt(text, text, text) RETURNS text

Purpose: Generates a self-signed certificate (or a CA certificate)
Param 1: CSR
Param 2: Path to the CA certificate OR NULL if generating a CA certificate.
Param 3: Path to the CA private key OR path to a private key, If param2 is NULL.
Returns: The certificate.

openssl_rsa_generate_crl(text, text) RETURNS text

Purpose: Generates a default certificate revocation list.
Param 1: Path to CA certificate.
Param 2: Path to CA private key.
Returns: The CRL.


========================================================
This extension is released under the PostgreSQL Licence.

Copyright (c) 2010 - 2016, EnterpriseDB Corporation.
