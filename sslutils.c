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
#include "utils/datetime.h"

#define SERIAL_RAND_BITS  64
#define VALIDITY_DAYS  3650

#define BUFFER_PADDING_BYTES 50

#define DB_NUMBER   6
#define DB_name     5
#define DB_file     4
#define DB_serial   3
#define DB_rev_date 2
#define DB_exp_date 1
#define DB_type     0

#define OCSP_REVOKED_STATUS_NOSTATUS         -1
#define OCSP_REVOKED_STATUS_KEYCOMPROMISE     1
#define OCSP_REVOKED_STATUS_CACOMPROMISE      2
#define OCSP_REVOKED_STATUS_CERTIFICATEHOLD   6
#define OCSP_REVOKED_STATUS_REMOVEFROMCRL     8

static const char* crl_reasons[] = {
	// CRL reason strings
	"unspecified",
	"keyCompromise",
	"CACompromise",
	"affiliationChanged",
	"superseded",
	"cessationOfOperation",
	"certificateHold",
	"removeFromCRL",
	// Additional pseudo reasons
	"holdInstruction",
	"keyTime",
	"CAkeyTime"
};

#define NUM_REASONS (sizeof(crl_reasons) / sizeof(char *))

PG_MODULE_MAGIC;

extern void _PG_init(void);
extern Datum openssl_rsa_generate_key(PG_FUNCTION_ARGS);
extern Datum openssl_rsa_key_to_csr(PG_FUNCTION_ARGS);
extern Datum openssl_csr_to_crt(PG_FUNCTION_ARGS);
extern Datum openssl_rsa_generate_crl(PG_FUNCTION_ARGS);
extern Datum sslutils_version(PG_FUNCTION_ARGS);
extern Datum openssl_is_crt_expire_on(PG_FUNCTION_ARGS);
extern Datum openssl_revoke_certificate(PG_FUNCTION_ARGS);
extern Datum openssl_get_crt_expiry_date(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(openssl_rsa_generate_key);
PG_FUNCTION_INFO_V1(openssl_rsa_key_to_csr);
PG_FUNCTION_INFO_V1(openssl_csr_to_crt);
PG_FUNCTION_INFO_V1(openssl_rsa_generate_crl);
PG_FUNCTION_INFO_V1(sslutils_version);
PG_FUNCTION_INFO_V1(openssl_is_crt_expire_on);
PG_FUNCTION_INFO_V1(openssl_revoke_certificate);
PG_FUNCTION_INFO_V1(openssl_get_crt_expiry_date);

#define PEM_SSLUTILS_VERSION "1.2"

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

static char* string_sep(char **stringp, const char *delim)
{
    char *start = *stringp, *p = start ? strpbrk(start, delim) : NULL;

    if (!p) {
        *stringp = NULL;
    } else {
        *p = 0;
        *stringp = p + 1;
    }

    return start;
}

/*
 * This function make certificate revocation string.
 */
static char* make_revocation_str()
{
	char* str;
	ASN1_UTCTIME* revtm = NULL;
	int i;

	revtm = X509_gmtime_adj(NULL, 0);

	if (!revtm)
		return NULL;

	i = revtm->length + 1;

	str = OPENSSL_malloc(i);

	if (!str)
		return NULL;

	BUF_strlcpy(str, (char *)revtm->data, i);
	ASN1_UTCTIME_free(revtm);

	return str;
}

/*
 * This function revoke client certificate and add entry in database file.
 */
static int revoke(const char* dbfile, X509* x)
{
	int i;
	ASN1_UTCTIME* tm = NULL;
	char* rev_str = NULL;
	BIGNUM* bn = NULL;
	char* row[DB_NUMBER];
        FILE *f = NULL;
	char line[512] = {0};

	for (i = 0; i < DB_NUMBER; i++)
		row[i] = NULL;

	row[DB_name] = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
	bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x), NULL);

	if (bn == NULL)
		return -1;

	if (BN_is_zero(bn))
		row[DB_serial] = BUF_strdup("00");
	else
		row[DB_serial] = BN_bn2hex(bn);

	BN_free(bn);

	if (row[DB_name] == NULL || row[DB_serial] == NULL)
		return -1;

	// open database file in append to add certificate to be revoked.
	f = fopen(dbfile, "a+");
	if (f == NULL)
		return -1;

	// Lookup whether the client cert has been revoke by serial number
	// and rotate the index.txt
	while (fgets(line, 512, f))
	{
		char* sep = "\t";
		char* token;
		int j = 0;

		char* p = line;
		while ((token = string_sep(&p, sep)) != NULL)
		{
			if (++j == DB_serial + 1)
			{
				if (strcmp(row[DB_serial], token) == 0)
				{
					// serial number already found in CRL file.
					fclose(f);
					return -1;
				}
				break;
			}
		}
	}

	// Insert new record to index.txt
	row[DB_type] = (char *)OPENSSL_malloc(2);

	tm = X509_get_notAfter(x);
	row[DB_exp_date] = (char *)OPENSSL_malloc(tm->length + 1);
	memcpy(row[DB_exp_date], tm->data, tm->length);
	row[DB_exp_date][tm->length] = '\0';

	row[DB_rev_date] = NULL;
	row[DB_file] = (char *)OPENSSL_malloc(8);

	if (row[DB_type] == NULL || row[DB_exp_date] == NULL || row[DB_file] == NULL)
		return -1;

	BUF_strlcpy(row[DB_file], "unknown", 8);
	row[DB_type][0] = 'V';
	row[DB_type][1] = '\0';

	rev_str = make_revocation_str();
	if (rev_str == NULL)
		return -1;

	row[DB_type][0] = 'R';
	row[DB_type][1] = '\0';
	row[DB_rev_date] = rev_str;

	for (i = 0; i < DB_NUMBER; i++)
	{
		if (row[i] != NULL)
		{
			fwrite(row[i], strlen(row[i]), 1, f);
			fwrite("\t", 1, 1, f);
			OPENSSL_free(row[i]);
		}
	}
	fwrite("\n", 1, 1, f);

	fclose(f);
	return 0;
}

/*
 * This function get the certificate revision information.
 */
static int unpack_revinfo(ASN1_TIME** prevtm, int* preason, ASN1_OBJECT** phold,
				   ASN1_GENERALIZEDTIME** pinvtm, const char* str)
{
	char* tmp = NULL;
	char* rtime_str, *reason_str = NULL, *arg_str = NULL, *p;
	int reason_code = -1;
	int ret = 0;
	unsigned int i;
	ASN1_OBJECT* hold = NULL;
	ASN1_GENERALIZEDTIME* comp_time = NULL;
	char errBuffer[512] = {0};
	tmp = BUF_strdup(str);

	if(!tmp)
	{
		sprintf (errBuffer, "memory allocation failure\n");
		goto err;
	}

	p = strchr(tmp, ',');
	rtime_str = tmp;

	if (p)
	{
		*p = '\0';
		p++;
		reason_str = p;
		p = strchr(p, ',');
		if (p)
		{
			*p = '\0';
			arg_str = p + 1;
		}
	}

	if (prevtm)
	{
		*prevtm = ASN1_UTCTIME_new();
		if(!*prevtm)
		{
			sprintf (errBuffer, "memory allocation failure\n");
			goto err;
		}
		if (!ASN1_UTCTIME_set_string(*prevtm, rtime_str))
		{
			sprintf (errBuffer, "invalid revocation date %s\n", rtime_str);
			goto err;
		}
	}
	if (reason_str)
	{
		for (i = 0; i < NUM_REASONS; i++)
		{
#ifdef WIN32
			if (!stricmp(reason_str, crl_reasons[i]))
#else
			if (!strcasecmp(reason_str, crl_reasons[i]))
#endif
			{
				reason_code = i;
				break;
			}
		}
		if (reason_code == OCSP_REVOKED_STATUS_NOSTATUS)
		{
			sprintf (errBuffer, "invalid reason code %s\n", reason_str);
			goto err;
		}

		if (reason_code == 7)
			reason_code = OCSP_REVOKED_STATUS_REMOVEFROMCRL;
		else if (reason_code == 8)
		{
			if (!arg_str)
			{
				sprintf (errBuffer, "missing hold instruction\n");
				goto err;
			}
			reason_code = OCSP_REVOKED_STATUS_CERTIFICATEHOLD;
			hold = OBJ_txt2obj(arg_str, 0);

			if (!hold)
			{
				sprintf (errBuffer, "invalid object identifier %s\n", arg_str);
				goto err;
			}
			if (phold)
				*phold = hold;
		}
		else if ((reason_code == 9) || (reason_code == 10))
		{
			if (!arg_str)
			{
				sprintf (errBuffer, "missing compromised time\n");
				goto err;
			}
			comp_time = ASN1_GENERALIZEDTIME_new();
			if(!comp_time)
			{
				sprintf (errBuffer, "memory allocation failure\n");
				goto err;
			}
			if (!ASN1_GENERALIZEDTIME_set_string(comp_time, arg_str))
			{
				sprintf (errBuffer, "invalid compromised time %s\n", arg_str);
				goto err;
			}
			if (reason_code == 9)
				reason_code = OCSP_REVOKED_STATUS_KEYCOMPROMISE;
			else
				reason_code = OCSP_REVOKED_STATUS_CACOMPROMISE;
		}
	}

	if (preason)
		*preason = reason_code;
	if (pinvtm)
		*pinvtm = comp_time;
	else
		ASN1_GENERALIZEDTIME_free(comp_time);

	ret = 1;

 err:
	if (tmp)
		OPENSSL_free(tmp);
	if (!phold)
		ASN1_OBJECT_free(hold);
	if (!pinvtm)
		ASN1_GENERALIZEDTIME_free(comp_time);
	if (errBuffer[0] != 0)
		report_openssl_error(errBuffer);

	return ret;
}

/*
 * Convert revocation field to X509_REVOKED entry
 * return code:
 * 0 error
 * 1 OK
 * 2 OK and some extensions added (i.e. V2 CRL)
 */
static int make_revoked(X509_REVOKED* rev, const char* str)
{
	char* tmp = NULL;
	int reason_code = -1;
	int i, ret = 0;
	ASN1_OBJECT* hold = NULL;
	ASN1_GENERALIZEDTIME* comp_time = NULL;
	ASN1_ENUMERATED* rtmp = NULL;

	ASN1_TIME* revDate = NULL;

	i = unpack_revinfo(&revDate, &reason_code, &hold, &comp_time, str);

	if (i == 0)
		goto err;

	if (rev && !X509_REVOKED_set_revocationDate(rev, revDate))
		goto err;

	if (rev && (reason_code != OCSP_REVOKED_STATUS_NOSTATUS))
	{
		rtmp = ASN1_ENUMERATED_new();
		if (!rtmp || !ASN1_ENUMERATED_set(rtmp, reason_code))
			goto err;
		if (!X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, rtmp, 0, 0))
			goto err;
	}

	if (rev && comp_time)
	{
		if (!X509_REVOKED_add1_ext_i2d(rev, NID_invalidity_date, comp_time, 0, 0))
			goto err;
	}
	if (rev && hold)
	{
		if (!X509_REVOKED_add1_ext_i2d
			(rev, NID_hold_instruction_code, hold, 0, 0))
			goto err;
	}

	if (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)
		ret = 2;
	else
		ret = 1;

err:
	if (tmp)
		OPENSSL_free(tmp);
	if (hold)
		ASN1_OBJECT_free(hold);
	if (comp_time)
		ASN1_GENERALIZEDTIME_free(comp_time);
	if (rtmp)
		ASN1_ENUMERATED_free(rtmp);
	if (revDate)
		ASN1_TIME_free(revDate);

	return ret;
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

	if (!X509_REQ_set_pubkey(req, evp))
	{
		err = "X509_REQ_set_pubkey";
		goto out;
	}

	if (!X509_REQ_sign(req, evp, EVP_sha256()))
	{
		err = "X509_REQ_sign";
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

	FILE       *fp_cert_file = NULL;
	FILE       *fp_key = NULL;

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
	if (fp_cert_file != NULL)
		fclose(fp_cert_file);
	if (fp_key != NULL)
		fclose(fp_key);
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

	FILE       *fp_cert_file = NULL;
	FILE       *fp_key = NULL;

	X509_CRL       *crl = NULL;
	EVP_PKEY       *pkey = NULL;
	ASN1_TIME      *tmptm = NULL;
	X509_NAME      *xn = NULL;

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

	if (!X509_gmtime_adj(tmptm, (long)60 * 60 * 24 * VALIDITY_DAYS))
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
	if (fp_cert_file != NULL)
		fclose(fp_cert_file);
	if (fp_key != NULL)
		fclose(fp_key);
	PG_RETURN_TEXT_P(res);
}


/*
 * SSLUtils Version
 *
 */
Datum
sslutils_version(PG_FUNCTION_ARGS)
{
	/* Construct return value. */
	PG_RETURN_TEXT_P(cstring_to_text_with_len(PEM_SSLUTILS_VERSION, strlen(PEM_SSLUTILS_VERSION)));
}

/*
* Return certificate is expire in given N Days.
*
*/
Datum
openssl_is_crt_expire_on(PG_FUNCTION_ARGS)
{
	text			*cert_file_path = NULL;
	X509			*cert = NULL;
	ASN1_TIME		*not_after = NULL;
	char			*err = NULL;

	if (PG_ARGISNULL(0))
	{
		err = "CERTIFICATE_FILE_IS_NULL";
		goto out;
	}

	cert_file_path = PG_GETARG_TEXT_PP(0);
	FILE *fp_cert_file = fopen(text_to_cstring(cert_file_path), "r");
	if (!fp_cert_file)
	{
		err = "FILE_OPEN_CA_CERT";
		goto out;
	}

	cert = PEM_read_X509(fp_cert_file, NULL, NULL, NULL);
	if (!cert)
	{
		err = "PEM_read_X509";
		goto out;
	}

	not_after = X509_get_notAfter(cert);
	if (!not_after)
	{
		err = "X509_get_notAfter";
		goto out;
	}

	if (PG_ARGISNULL(1))
	{
		err = "COMPARE_TIME_IS_NULL";
		goto out;
	}

	TimestampTz cmp_time = PG_GETARG_TIMESTAMPTZ(1);
	// Convert timestamptz to time_t for comparision.
	time_t t= timestamptz_to_time_t(cmp_time);
	// Compare the end date of certificate with given date.
	int retVal = X509_cmp_time(not_after, &t);

	/* Get out, while trying not to leak memory. */
out:
	if (cert != NULL)
		X509_free(cert);
	if (fp_cert_file != NULL)
		fclose(fp_cert_file);
	if (err != NULL)
		report_openssl_error(err);

	PG_RETURN_INT32(retVal);
}

/*
 * Revoke the client certificate and Re-generate CRL.
 */
Datum
openssl_revoke_certificate(PG_FUNCTION_ARGS)
{
	text       *cert_t_data = NULL;
	text       *t_crl_filename = NULL;

	X509       *cacert = NULL;
	EVP_PKEY   *pkey = NULL;
	X509_CRL   *crl = NULL;
	ASN1_TIME  *tmptm = NULL;
	BIO        *sout = NULL;
	BIO        *bio_mem = NULL;
	X509_NAME  *xn = NULL;
	X509       *x = NULL;
	BIGNUM     *serial = NULL;
	FILE       *f = NULL;
	FILE       *f1 = NULL;

	BIO        *bio = NULL;
	char       *err = NULL;
	char       *data = NULL;
	long       len;
	text       *res = NULL;
	char       line[512];
	char       *cert_data = NULL;
	int        cert_data_size = 0;
	char       *c_crl_filename = NULL;
	char       *crl_file_buffer = NULL;
	int        crl_file_len = 0;
	char       *ca_cert_file = "ca_certificate.crt";
	char       *ca_key_file = "ca_key.key";
	char       *revoke_cert_db_file = "revoke_cert.db";

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
	{
		err = "INVALID_ARGUMENTS";
		goto out;
	}

	cert_t_data        = PG_GETARG_TEXT_PP(0);
	t_crl_filename     = PG_GETARG_TEXT_PP(1);

	c_crl_filename  = text_to_cstring(t_crl_filename);
	crl_file_len = strlen(c_crl_filename);

	cert_data_size = strlen(text_to_cstring(cert_t_data)) + 1;
	cert_data = OPENSSL_malloc(cert_data_size + 10);

	if (!cert_data)
	{
		err = "ERROR_MALLOC_CERT_DATA";
		goto out;
	}

	BUF_strlcpy(cert_data, text_to_cstring(cert_t_data), cert_data_size);

	// Create a buffer to read the certificate data.
	bio = BIO_new_mem_buf((void*)cert_data, cert_data_size);
	if (bio == NULL)
	{
		err = "ERROR_BIO_NEW";
		goto out;
	}

	if (!PEM_read_bio_X509(bio, &x, 0, NULL))
	{
		err = "ERROR_READ_BIO_X509";
		goto out;
	}

	// First add certificate to database file index.txt which contains list of revoke certificates.
	int ret = revoke(revoke_cert_db_file, x);
	if (ret == -1)
	{
		err = "ADD_CERT_TO_DB_FILE";
		goto out;
	}

	/* load cacert */
	cacert = X509_new();
	if (cacert == NULL)
	{
		err = "ERROR_X509_NEW";
		goto out;
	}

	f = fopen(ca_cert_file, "r");
	if (f == NULL)
	{
		err = "FILE_OPEN_CA_CERT";
		goto out;
	}

	PEM_read_X509(f, &cacert, NULL, NULL);
	fclose(f);

	/* load cakey */
	pkey = EVP_PKEY_new();
	if (pkey == NULL)
	{
		err = "ERROR_CA_KEY_NEW";
		goto out;
	}

	f = fopen(ca_key_file, "r");
	if (f == NULL)
	{
		err = "ERROR_OPEN_CA_KEY";
		goto out;
	}

	PEM_read_PrivateKey(f, &pkey, NULL, NULL);
	fclose(f);

	crl = X509_CRL_new();
	if (crl == NULL)
	{
		err = "ERROR_X509_CRL_NEW";
		goto out;
	}

	/* Set the CRL issuer name as CA's name  */
	if (!X509_CRL_set_issuer_name(crl, cacert ? X509_get_subject_name(cacert) : X509_NAME_dup(xn)))
	{
		err = "CRL_SET_ISSUER_NAME";
		goto out;
	}

	/* Add timestamp to CRL */
	tmptm = ASN1_TIME_new();
	if (tmptm == NULL)
	{
		err = "error getting new time";
		goto out;
	}

	X509_gmtime_adj(tmptm, 0);
	X509_CRL_set_lastUpdate(crl, tmptm);

	if (!X509_gmtime_adj(tmptm, (long)60 * 60 * 24 * VALIDITY_DAYS))
	{
		err = "error setting CRL nextUpdate";
		goto out;
	}

	X509_CRL_set_nextUpdate(crl, tmptm);

	/*
	 * Read every serial number from revoke certificate db file and create a
	 * X509_REVOKED: r with serial number, and insert r to CRL.
	 */
	f1 = fopen(revoke_cert_db_file, "r");
	if (f1 == NULL)
	{
		err = "ERROR_OPEN_DB_FILE";
		goto out;
	}

	while (fgets(line, 512, f1))
	{
		if (line[0] != 'R')
			continue;

		char fileds[6][64];
		char* sep = "\t";
		char* token;
		int k = 0;
		char* p = line;
		while ((token = string_sep(&p, sep)) != NULL)
		{
			strcpy(fileds[k++], token);
		}

		X509_REVOKED* r = X509_REVOKED_new();
		if (r == NULL)
			goto out;

		int retVal = make_revoked(r, fileds[DB_rev_date]);
		if (retVal <= 0)
			goto out;
		retVal = BN_hex2bn(&serial, fileds[DB_serial]);
		if (retVal <= 0)
			goto out;

		ASN1_INTEGER* tmpser = BN_to_ASN1_INTEGER(serial, NULL);
		BN_free(serial);
		serial = NULL;

		if (tmpser == NULL)
			goto out;

		X509_REVOKED_set_serialNumber(r, tmpser);
		ASN1_INTEGER_free(tmpser);
		X509_CRL_add0_revoked(crl, r);
	}

	fclose(f1);
	X509_CRL_sort(crl);

	/* Sign the CRL */
	if (!X509_CRL_sign(crl, pkey, EVP_sha1()))
	{
		err = "Error_signing_crl";
		goto out;
	}

	sout = BIO_new(BIO_s_file());
	if (sout == NULL)
	{
		err = "Error_BIO_NEW";
		goto out;
	}

	crl_file_buffer = OPENSSL_malloc(crl_file_len + BUFFER_PADDING_BYTES);
	if (!crl_file_buffer)
	{
		err = "ERROR_MALLOC_CRL_BUFFER";
		goto out;
	}

	memset(crl_file_buffer, 0x00, (crl_file_len + BUFFER_PADDING_BYTES));
	memcpy(crl_file_buffer, c_crl_filename, (crl_file_len + 1));

	if (!BIO_write_filename(sout, crl_file_buffer))
	{
		err = "PEM_write_bio_X509_CRL";
		goto out;
	}

	if (!PEM_write_bio_X509_CRL(sout, crl))
	{
		err = "PEM_write_bio_X509_CRL";
		goto out;
	}

	/* Construct return value. */
	bio_mem = BIO_new(BIO_s_mem());
	if (!bio_mem)
	{
		err = "BIO_new";
		goto out;
	}
	if (!PEM_write_bio_X509_CRL(bio_mem, crl))
	{
		err = "PEM_write_bio_X509_REQ";
		goto out;
	}

	len = BIO_get_mem_data(bio_mem, &data);
	res = cstring_to_text_with_len(data, len);

	/* Get out, while trying not to leak memory. */
out:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (bio != NULL)
		BIO_free(bio);
	if (tmptm != NULL)
		ASN1_TIME_free(tmptm);
	if (x != NULL)
		X509_free(x);
	if (cacert)
		X509_free(cacert);
	if (crl)
		X509_CRL_free(crl);
	if (sout)
		BIO_free(sout);
	if (bio_mem)
		BIO_free(bio_mem);
	if (cert_data)
		OPENSSL_free(cert_data);
	if (crl_file_buffer)
		OPENSSL_free(crl_file_buffer);
	if (err != NULL)
		report_openssl_error(err);

	PG_RETURN_TEXT_P(res);
}

/*
* Convert ASN1_TIME to tm.
*
*/
time_t
ASN1_GetTimeT(ASN1_TIME* time)
{
	struct tm t;
	const char* str = (const char*)time->data;
	size_t i = 0;

	memset(&t, 0, sizeof(t));

	if (time->type == V_ASN1_UTCTIME) {/* two digit year */
		t.tm_year = (str[i++] - '0') * 10;
		t.tm_year += (str[i++] - '0');
		if (t.tm_year < 70)
			t.tm_year += 100;
	}
	else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
		t.tm_year = (str[i++] - '0') * 1000;
		t.tm_year += (str[i++] - '0') * 100;
		t.tm_year += (str[i++] - '0') * 10;
		t.tm_year += (str[i++] - '0');
		t.tm_year -= 1900;
	}

	t.tm_mon = (str[i++] - '0') * 10;
	t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
	t.tm_mday = (str[i++] - '0') * 10;
	t.tm_mday += (str[i++] - '0');
	t.tm_hour = (str[i++] - '0') * 10;
	t.tm_hour += (str[i++] - '0');
	t.tm_min = (str[i++] - '0') * 10;
	t.tm_min += (str[i++] - '0');
	t.tm_sec = (str[i++] - '0') * 10;
	t.tm_sec += (str[i++] - '0');

	/* Note: we did not adjust the time based on time zone information */
	return mktime(&t);
}

/*
* Return certificate's expiry date.
*
*/
Datum
openssl_get_crt_expiry_date(PG_FUNCTION_ARGS)
{
	text			*cert_file_path = NULL;
	X509			*cert = NULL;
	ASN1_TIME		*not_after = NULL;
	char			*err = NULL;

	if (PG_ARGISNULL(0))
	{
		err = "CERTIFICATE_FILE_IS_NULL";
		goto out;
	}

	cert_file_path = PG_GETARG_TEXT_PP(0);
	FILE *fp_cert_file = fopen(text_to_cstring(cert_file_path), "r");
	if (!fp_cert_file)
	{
		err = "FILE_OPEN_CA_CERT";
		goto out;
	}

	cert = PEM_read_X509(fp_cert_file, NULL, NULL, NULL);
	if (!cert)
	{
		err = "PEM_read_X509";
		goto out;
	}

	not_after = X509_get_notAfter(cert);
	if (!not_after)
	{
		err = "X509_get_notAfter";
		goto out;
	}

	// Convert ASN1_TIME to time_t.
	time_t tNotAfter = ASN1_GetTimeT(not_after);
	// Convert time_t to TimestampTz.
	TimestampTz timeTZ = time_t_to_timestamptz(tNotAfter);

	/* Get out, while trying not to leak memory. */
out:
	if (cert != NULL)
		X509_free(cert);
	if (fp_cert_file != NULL)
		fclose(fp_cert_file);
	if (err != NULL)
		report_openssl_error(err);

	PG_RETURN_TIMESTAMPTZ(timeTZ);
}

