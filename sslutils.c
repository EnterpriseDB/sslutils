/*
 * OpenSSL library access from PostgreSQL
 */

#include "postgres.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509v3.h>

#include "fmgr.h"
#include "utils/builtins.h"

#define SERIAL_RAND_BITS  64
#define VALIDITY_DAYS  3650

PG_MODULE_MAGIC;

extern void _PG_init(void);
extern Datum openssl_rsa_generate_key(PG_FUNCTION_ARGS);
extern Datum openssl_rsa_key_to_csr(PG_FUNCTION_ARGS);
extern Datum openssl_csr_to_crt(PG_FUNCTION_ARGS);
extern Datum openssl_rsa_generate_crl(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(openssl_rsa_generate_key);
PG_FUNCTION_INFO_V1(openssl_rsa_key_to_csr);
PG_FUNCTION_INFO_V1(openssl_csr_to_crt);
PG_FUNCTION_INFO_V1(openssl_rsa_generate_crl);

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
	text	   *country = PG_GETARG_TEXT_PP(2);
	text	   *state = PG_GETARG_TEXT_PP(3);
	text	   *city = PG_GETARG_TEXT_PP(4);
	text       *organization = cstring_to_text("EnterpriseDB Corporation");
	text       *organization_unit = PG_GETARG_TEXT_PP(5);
	text	   *email = PG_GETARG_TEXT_PP(6);
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
	name = X509_REQ_get_subject_name(req);;
	if (!name)
	{
		err = "X509_REQ_get_subject_name";
		goto out;
	}
	if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_UTF8,
	                                (unsigned char *) VARDATA_ANY(country),
	                                VARSIZE_ANY_EXHDR(country), -1, 0))
	{
		err = "X509_NAME_add_entry_by_txt_C";
		goto out;
	}
	if (!X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_UTF8,
	                                (unsigned char *) VARDATA_ANY(state),
	                                VARSIZE_ANY_EXHDR(state), -1, 0))
	{
		err = "X509_NAME_add_entry_by_txt_ST";
		goto out;
	}
	if (!X509_NAME_add_entry_by_txt(name, "L", MBSTRING_UTF8,
	                                (unsigned char *) VARDATA_ANY(city),
	                                VARSIZE_ANY_EXHDR(city), -1, 0))
	{
		err = "X509_NAME_add_entry_by_txt_L";
		goto out;
	}
	if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8,
	                                (unsigned char *) VARDATA_ANY(organization),
	                                VARSIZE_ANY_EXHDR(organization), -1, 0))
	{
		err = "X509_NAME_add_entry_by_txt_O";
		goto out;
	}
	if (!X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_UTF8,
	                                (unsigned char *) VARDATA_ANY(organization_unit),
	                                VARSIZE_ANY_EXHDR(organization_unit), -1, 0))
	{
		err = "X509_NAME_add_entry_by_txt_OU";
		goto out;
	}

	if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
	                                (unsigned char *) VARDATA_ANY(cn),
	                                VARSIZE_ANY_EXHDR(cn), -1, 0))
	{
		err = "X509_NAME_add_entry_by_txt_CN";
		goto out;
	}
	if (!X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_UTF8,
	                                (unsigned char *) VARDATA_ANY(email),
	                                VARSIZE_ANY_EXHDR(email), -1, 0))
	{
		err = "X509_NAME_add_entry_by_txt_emailAddress";
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

/*
 * Generate an X509, also known as a CRT.
 *
 */
Datum
openssl_csr_to_crt(PG_FUNCTION_ARGS)
{
	text       *csr = NULL;
	text       *ca_cert_file_path = NULL;
	text       *ca_key_file_path = NULL;
	BIO        *bio = NULL;
	RSA        *ca_key = NULL;
	char       *err = NULL;
	X509_REQ   *req = NULL;
	X509       *ca_cert = NULL;
	char       *data = NULL;
	long       len;
	text       *res = NULL;

	FILE       *fp_cert_file;
	FILE       *fp_key;

	X509           *certificate = NULL;
	EVP_PKEY       *pkey = NULL;
	X509_EXTENSION *extension = NULL;
	ASN1_INTEGER   *serial_no = NULL;
	BIGNUM         *bn = NULL;
	X509V3_CTX     ctx;
	X509_CINF *xi = NULL;
	X509_NAME *xn;

	if (PG_ARGISNULL(0))
	{
		err = "CSR_IS_NULL";
		goto out;
	}
	csr = PG_GETARG_TEXT_PP(0);
	if (!PG_ARGISNULL(1))
	{
		ca_cert_file_path = PG_GETARG_TEXT_PP(1);

		/* Get the CA certificate */
		fp_cert_file = fopen(text_to_cstring(ca_cert_file_path), "r");
		if (!fp_cert_file)
		{
			err = "FILE_OPEN_CA_CERT";
			goto out;
		}
		ca_cert = PEM_read_X509(fp_cert_file, NULL, NULL, NULL);
		if (!ca_cert)
		{
			err = "PEM_read_X509";
			goto out;
		}
	}

	if (PG_ARGISNULL(2))
	{
		err = "PRIVATE_KEY_IS_NULL";
		goto out;
	}
	ca_key_file_path = PG_GETARG_TEXT_PP(2);

	/* Get the CA private key */
	fp_key = fopen(text_to_cstring(ca_key_file_path), "r");
	if (!fp_key)
	{
		err = "FILE_OPEN_CA_KEY";
		goto out;
	}
	ca_key = PEM_read_RSAPrivateKey(fp_key, NULL, NULL, NULL);
	if (!ca_key)
	{
		err = "PEM_read_RSAPrivateKey";
		goto out;
	}

	/* Decode csr to X509_REQ */
	bio = BIO_new_mem_buf(VARDATA_ANY(csr), VARSIZE_ANY_EXHDR(csr));
	if (!bio)
	{
		err = "BIO_new_mem_buf";
		goto out;
	}
	req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	BIO_free(bio);
	bio = NULL;
	if (!req)
	{
		err = "PEM_read_bio_X509_REQ";
		goto out;
	}
	/* Use EVP_PKEY to bind RSA to X509_REQ. */
	pkey = EVP_PKEY_new();
	if (!pkey)
	{
		err = "EVP_PKEY_new";
		goto out;
	}
	if (!EVP_PKEY_set1_RSA(pkey, ca_key))
	{
		err = "EVP_PKEY_assign_RSA";
		goto out;
	}

	certificate = X509_new();
	if (!certificate)
	{
		err = "Error_creating_certificate";
		goto out;
	}
	xi = certificate->cert_info;
	xn = X509_REQ_get_subject_name(req);
	if (!xn)
	{
		err = "Error_getting_subject_name";
		goto out;
	}
	if (!X509_set_subject_name(certificate, X509_NAME_dup(xn)))
	{
		err = "Error_setting_subject_name";
		goto out;
	}

	if (!X509_gmtime_adj(xi->validity->notBefore, 0))
	{
		err = "Error_setting_validity_before_time";
		goto out;
	}

	if (!X509_gmtime_adj(xi->validity->notAfter, (long)60 * 60 * 24 * VALIDITY_DAYS))
	{
		err = "Error_setting_validity_before_time";
		goto out;
	}

	if(!X509_set_pubkey(certificate, X509_REQ_get_pubkey(req)))
	{
		err = "Error_setting_public_key";
		goto out;
	}

	if (!X509_set_issuer_name(certificate, ca_cert ? X509_get_subject_name(ca_cert) : X509_NAME_dup(xn)))
	{
		err = "Error_setting_issuer_name";
		goto out;
	}

	serial_no = ASN1_INTEGER_new();
	if (!serial_no)
	{
		err = "Error_allocating_memory_for_serial";
		goto out;
	}

	bn = BN_new();
	if (!bn)
	{
		err = "Error_allocating_memory_for_bignum";
		goto out;
	}

	if (!BN_pseudo_rand(bn, SERIAL_RAND_BITS, 0, 0))
	{
		err = "Error_generating_random_bignum";
		goto out;
	}

	serial_no = BN_to_ASN1_INTEGER(bn, serial_no);
	if (!serial_no)
	{
		err = "Error_converting_bignum_to_ASN1_INTEGER";
		goto out;
	}

	if (!X509_set_serialNumber(certificate, serial_no))
	{
		err = "Error_setting_serialNumber";
		goto out;
	}

	X509V3_set_ctx(&ctx, ca_cert , certificate, NULL, NULL, 0);
	extension = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, (char *)"hash");
	if (!extension)
	{
		err = "Error_adding_extension_subject_key_identifier";
		goto out;
	}
	X509_add_ext(certificate, extension, -1);

	X509V3_set_ctx(&ctx, ca_cert , certificate, NULL, NULL, 0);
	if (ca_cert)
		X509V3_set_ctx(&ctx, ca_cert , certificate, NULL, NULL, 0);
	else
		X509V3_set_ctx(&ctx, certificate , certificate, NULL, NULL, 0);
	extension = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, (char *)"keyid:always");

	if (!extension)
	{
		err = "Error_adding_extension_authority_key_identifier";
		goto out;
	}
	X509_add_ext(certificate, extension, -1);
	if (!ca_cert)
	{
		X509V3_set_ctx(&ctx, ca_cert , certificate, NULL, NULL, 0);
		extension = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, (char *)"CA:TRUE");
		if (!extension)
		{
			err = "Error_adding_extension_basic_constraints";
			goto out;
		}
		X509_add_ext(certificate, extension, -1);
	}

	if (!X509_sign(certificate, pkey, EVP_sha1()))
	{
		err = "Error_signing_certificate";
		goto out;
	}

	/* Write X509 out in PEM format. */
	bio = BIO_new(BIO_s_mem());
	if (!bio)
	{
		err = "BIO_new";
		goto out;
	}
	if (!PEM_write_bio_X509(bio, certificate))
	{
		err = "PEM_write_bio_X509";
		goto out;
	}

	/* Construct return value. */
	len = BIO_get_mem_data(bio, &data);
	res = cstring_to_text_with_len(data, len);

	/* Get out, while trying not to leak memory. */
out:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (req != NULL)
		X509_REQ_free(req);
	if (ca_cert != NULL)
		X509_free(ca_cert);
	if (ca_key != NULL)
		RSA_free(ca_key);
	if (bio != NULL)
		BIO_free(bio);
	if (extension != NULL)
		X509_EXTENSION_free(extension);
	if (serial_no != NULL)
		ASN1_INTEGER_free(serial_no);
	if (err != NULL)
		report_openssl_error(err);
	PG_RETURN_TEXT_P(res);
}

/*
 * Generate an X509_CRL, also known as a CRL.
 *
 */
Datum
openssl_rsa_generate_crl(PG_FUNCTION_ARGS)
{
	text       *ca_cert_file_path = NULL;
	text       *ca_key_file_path = NULL;
	BIO        *bio = NULL;
	RSA        *ca_key = NULL;
	char       *err = NULL;
	X509       *ca_cert = NULL;
	char       *data = NULL;
	long       len;
	text       *res = NULL;

	FILE       *fp_cert_file;
	FILE       *fp_key;

	X509_CRL       *crl = NULL;
	EVP_PKEY       *pkey = NULL;
	ASN1_TIME      *tmptm = NULL;
	X509_NAME *xn;

	if (!PG_ARGISNULL(0))
	{
		ca_cert_file_path = PG_GETARG_TEXT_PP(0);

		/* Get the CA crl */
		fp_cert_file = fopen(text_to_cstring(ca_cert_file_path), "r");
		if (!fp_cert_file)
		{
			err = "FILE_OPEN_CA_CERT";
			goto out;
		}
		ca_cert = PEM_read_X509(fp_cert_file, NULL, NULL, NULL);
		if (!ca_cert)
		{
			err = "PEM_read_X509";
			goto out;
		}
	}

	if (PG_ARGISNULL(1))
	{
		err = "PRIVATE_KEY_IS_NULL";
		goto out;
	}
	ca_key_file_path = PG_GETARG_TEXT_PP(1);

	/* Get the CA private key */
	fp_key = fopen(text_to_cstring(ca_key_file_path), "r");
	if (!fp_key)
	{
		err = "FILE_OPEN_CA_KEY";
		goto out;
	}
	ca_key = PEM_read_RSAPrivateKey(fp_key, NULL, NULL, NULL);
	if (!ca_key)
	{
		err = "PEM_read_RSAPrivateKey";
		goto out;
	}


        /* Use EVP_PKEY to bind RSA to X509_REQ. */
        pkey = EVP_PKEY_new();
        if (!pkey)
        {
                err = "EVP_PKEY_new";
                goto out;
        }
        if (!EVP_PKEY_set1_RSA(pkey, ca_key))
        {
                err = "EVP_PKEY_assign_RSA";
                goto out;
        }

	/* Create an empty CRL */
	crl = X509_CRL_new();
	if (!crl)
	{
		err = "Error_creating_crl";
		goto out;
	}

	/* Set the CRL issuer name as CA's name  */
        if (!X509_CRL_set_issuer_name(crl, ca_cert ? X509_get_subject_name(ca_cert) : X509_NAME_dup(xn)))
        {
                err = "Error_setting_issuer_name";
                goto out;
        }

	/* Add timestamp to CRL */
        tmptm = ASN1_TIME_new();
        if (!tmptm)
        {
                err = "error getting new time";
                goto out;
        }
        X509_gmtime_adj(tmptm,0);
        X509_CRL_set_lastUpdate(crl, tmptm);

        if (!X509_time_adj_ex(tmptm, VALIDITY_DAYS, 1*60*60 + 0, NULL))
        {
                 err = "error setting CRL nextUpdate";
                 goto out;
        }

        X509_CRL_set_nextUpdate(crl, tmptm);

        X509_CRL_sort(crl);

	/* Sign the CRL */
	if (!X509_CRL_sign(crl, pkey, EVP_sha1()))
	{
		err = "Error_signing_crl";
		goto out;
	}

	/* Write X509 out in PEM format. */
	bio = BIO_new(BIO_s_mem());
	if (!bio)
	{
		err = "BIO_new";
		goto out;
	}
	if (!PEM_write_bio_X509_CRL(bio, crl))
	{
		err = "PEM_write_bio_X509_CRL";
		goto out;
	}

	/* Construct return value. */
	len = BIO_get_mem_data(bio, &data);
	res = cstring_to_text_with_len(data, len);

	/* Get out, while trying not to leak memory. */
out:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (ca_cert != NULL)
		X509_free(ca_cert);
	if (ca_key != NULL)
		RSA_free(ca_key);
	if (bio != NULL)
		BIO_free(bio);
	if (tmptm != NULL)
		ASN1_TIME_free(tmptm);
	if (err != NULL)
		report_openssl_error(err);
	PG_RETURN_TEXT_P(res);
}
