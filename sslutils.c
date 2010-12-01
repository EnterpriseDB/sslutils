/*
 * OpenSSL library access from PostgreSQL
 */

#include "postgres.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include "fmgr.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;

extern void _PG_init(void);
extern Datum openssl_rsa_generate_key(PG_FUNCTION_ARGS);
extern Datum openssl_rsa_key_to_csr(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(openssl_rsa_generate_key);
PG_FUNCTION_INFO_V1(openssl_rsa_key_to_csr);

/* On module load, make sure SSL error strings are available. */
void
_PG_init(void)
{
	SSL_load_error_strings();
}

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
	int			bits = PG_GETARG_INT32(0);
	RSA		   *rsa = NULL;
	BIO		   *bio = NULL;
	char	   *err = NULL;
	char	   *data = NULL;
	long		len;
	text	   *res = NULL;

	/*
	 * Don't allow too many bits.  It takes a long time, and since
	 * RSA_generate_key() is an external library function, it's not
	 * interruptible.
	 */
	if (bits > 8192)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("maximum number of bits is 8192")));

	/* Generate key. */
	rsa = RSA_generate_key(bits, 65537, NULL, NULL);
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

/*
 * Generate an X509_REQ, also known as a CSR.
 *
 * We currently support only the "CN" attribute, since that's the only thing
 * that PostgreSQL cares about for client authentication.
 */
Datum
openssl_rsa_key_to_csr(PG_FUNCTION_ARGS)
{
	text	   *key = PG_GETARG_TEXT_PP(0);
	text	   *cn = PG_GETARG_TEXT_PP(1);
	BIO		   *bio = NULL;
	RSA		   *rsa = NULL;
	char	   *err = NULL;
	X509_REQ   *req = NULL;
	EVP_PKEY   *evp = NULL;
	X509_NAME  *name = NULL;
	char	   *data = NULL;
	long		len;
	text	   *res = NULL;

	/* Decode key to RSA. */
	bio = BIO_new_mem_buf(VARDATA_ANY(key), VARSIZE_ANY_EXHDR(key));
	if (!bio)
	{
		err = "BIO_new_mem_buf";
		goto out;
	}
	rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);
	bio = NULL;
	if (!rsa)
	{
		err = "PEM_read_bio_RSAPrivateKey";
		goto out;
	}

	/* Create X509_REQ structure. */
	req = X509_REQ_new();
	if (!req)
	{
		err = "X509_REQ_new";
		goto out;
	}	

	/* Use EVP_PKEY to bind RSA to X509_REQ. */
	evp = EVP_PKEY_new();
	if (!evp)
	{
		err = "EVP_PKEY_new";
		goto out;
	}
	if (!EVP_PKEY_set1_RSA(evp, rsa))
	{
		err = "EVP_PKEY_assign_RSA";
		goto out;
	}
	if (!X509_REQ_set_pubkey(req, evp))
	{
		err = "X509_REQ_set_pubkey";
		goto out;
	}

	/* Add attributes. */
	name = X509_REQ_get_subject_name(req);
	if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
									(unsigned char *) VARDATA_ANY(cn),
									VARSIZE_ANY_EXHDR(cn), -1, 0))
	{
		err = "X509_NAME_add_entry_by_txt";
		goto out;
	}

	/* Write X509_REQ out in PEM format. */
	bio = BIO_new(BIO_s_mem());
	if (!bio)
	{
		err = "BIO_new";
		goto out;
	}
	if (!PEM_write_bio_X509_REQ(bio, req))
	{
		err = "PEM_write_bio_X509_REQ";
		goto out;
	}

	/* Construct return value. */
	len = BIO_get_mem_data(bio, &data);
	res = cstring_to_text_with_len(data, len);

	/* Get out, while trying not to leak memory. */
out:
	if (evp != NULL)
		EVP_PKEY_free(evp);
	if (req != NULL)
		X509_REQ_free(req);
	if (rsa != NULL)
		RSA_free(rsa);
	if (bio != NULL)
		BIO_free(bio);
	if (err != NULL)
		report_openssl_error(err);
	PG_RETURN_TEXT_P(res);
}
