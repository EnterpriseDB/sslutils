/*
 * OpenSSL library access from PostgreSQL
 */

#include "postgres.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "fmgr.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;

extern Datum openssl_rsa_generate_key(PG_FUNCTION_ARGS);

/* Report an error within OpenSSL. */
static void
report_openssl_error(char *where)
{
	unsigned long	e = ERR_get_error();
	char	   *err = ERR_error_string(e, NULL);

	ereport(ERROR,
			(errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
			 errmsg("OpenSSL error (%s): %s", where, err)));
}

/*
 * Generate an RSA key.
 */
Datum
openssl_rsa_generate_key(PG_FUNCTION_ARGS)
{
	RSA		   *rsa = NULL;
	BIO		   *bio = NULL;
	char	   *err = NULL;
	char	   *data = NULL;
	long		len;
	text	   *res = NULL;

	/* Generate key. */
	rsa = RSA_generate_key(1024, 65537, NULL, NULL);
	if (!rsa)
	{
		err = "RSA_generate_key";
		goto out;
	}

	/* Set up output buffer. */
	bio = BIO_new(BIO_s_mem());
	if (!bio)
	{
		err = "BIO_new";
		goto out;
	}

	/* Write data to buffer. */
	if (!PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL))
	{
		err = "PEM_write_bio_RSAPrivateKey";
		goto out;
	}

	/* Construct return value. */
	len = BIO_get_mem_data(bio, &data);
	res = cstring_to_text_with_len(data, len);

	/* Get out, while trying not to leak memory. */
out:
	if (bio != NULL)
		BIO_free(bio);
	if (rsa != NULL)
		RSA_free(rsa);
	if (err != NULL)
		report_openssl_error(err);
	PG_RETURN_TEXT_P(res);
}
