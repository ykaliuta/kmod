/*
 * libkmod - module signature display
 *
 * Copyright (C) 2013 Michal Marek, SUSE
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include <endian.h>
#include <inttypes.h>
#ifdef ENABLE_GNUTLS
#include <gnutls/pkcs7.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/missing.h>
#include <shared/util.h>

#include "libkmod-internal.h"

/* These types and tables were copied from the 3.7 kernel sources.
 * As this is just description of the signature format, it should not be
 * considered derived work (so libkmod can use the LGPL license).
 */
enum pkey_algo {
	PKEY_ALGO_DSA,
	PKEY_ALGO_RSA,
	PKEY_ALGO__LAST
};

static const char *const pkey_algo[PKEY_ALGO__LAST] = {
	[PKEY_ALGO_DSA]		= "DSA",
	[PKEY_ALGO_RSA]		= "RSA",
};

enum pkey_hash_algo {
	PKEY_HASH_MD4,
	PKEY_HASH_MD5,
	PKEY_HASH_SHA1,
	PKEY_HASH_RIPE_MD_160,
	PKEY_HASH_SHA256,
	PKEY_HASH_SHA384,
	PKEY_HASH_SHA512,
	PKEY_HASH_SHA224,
	PKEY_HASH__LAST
};

const char *const pkey_hash_algo[PKEY_HASH__LAST] = {
	[PKEY_HASH_MD4]		= "md4",
	[PKEY_HASH_MD5]		= "md5",
	[PKEY_HASH_SHA1]	= "sha1",
	[PKEY_HASH_RIPE_MD_160]	= "rmd160",
	[PKEY_HASH_SHA256]	= "sha256",
	[PKEY_HASH_SHA384]	= "sha384",
	[PKEY_HASH_SHA512]	= "sha512",
	[PKEY_HASH_SHA224]	= "sha224",
};

enum pkey_id_type {
	PKEY_ID_PGP,		/* OpenPGP generated key ID */
	PKEY_ID_X509,		/* X.509 arbitrary subjectKeyIdentifier */
	PKEY_ID_PKCS7,		/* Signature in PKCS#7 message */
	PKEY_ID_TYPE__LAST
};

const char *const pkey_id_type[PKEY_ID_TYPE__LAST] = {
	[PKEY_ID_PGP]		= "PGP",
	[PKEY_ID_X509]		= "X509",
	[PKEY_ID_PKCS7]		= "PKCS#7",
};

/*
 * Module signature information block.
 */
struct module_signature {
	uint8_t algo;        /* Public-key crypto algorithm [enum pkey_algo] */
	uint8_t hash;        /* Digest algorithm [enum pkey_hash_algo] */
	uint8_t id_type;     /* Key identifier type [enum pkey_id_type] */
	uint8_t signer_len;  /* Length of signer's name */
	uint8_t key_id_len;  /* Length of key identifier */
	uint8_t __pad[3];
	uint32_t sig_len;    /* Length of signature data (big endian) */
};

static const char *pkey_hash_algo_to_str(enum pkey_hash_algo algo)
{
	if (algo < 0 || algo >= PKEY_HASH__LAST)
		return "unknown";
	return pkey_hash_algo[algo];
}

static bool fill_default(const char *mem, off_t size,
			 const struct module_signature *modsig, size_t sig_len,
			 struct kmod_signature_info *sig_info)
{
	size -= sig_len;
	sig_info->sig = mem + size;
	sig_info->sig_len = sig_len;

	size -= modsig->key_id_len;
	sig_info->key_id = mem + size;
	sig_info->key_id_len = modsig->key_id_len;

	size -= modsig->signer_len;
	sig_info->signer = mem + size;
	sig_info->signer_len = modsig->signer_len;

	sig_info->algo = pkey_algo[modsig->algo];
	sig_info->hash_algo = pkey_hash_algo[modsig->hash];
	sig_info->id_type = pkey_id_type[modsig->id_type];

	return true;
}

#ifdef ENABLE_GNUTLS

struct pkcs7_private {
	gnutls_pkcs7_t pkcs7;
	gnutls_pkcs7_signature_info_st si;
	gnutls_x509_dn_t dn;
	gnutls_datum_t dn_data;
	char *issuer;
};

static void pkcs7_free(void *s)
{
	struct kmod_signature_info *si = s;
	struct pkcs7_private *pvt = si->private;

	free(pvt->issuer);
	gnutls_free(pvt->dn_data.data);
	gnutls_x509_dn_deinit(pvt->dn);
	gnutls_pkcs7_signature_info_deinit(&pvt->si);
	gnutls_pkcs7_deinit(pvt->pkcs7);

	free(pvt);
	si->private = NULL;
}

static int gnutls_algo_translate(gnutls_sign_algorithm_t algo)
{
	switch (algo) {
	case GNUTLS_SIGN_RSA_SHA1:
	case GNUTLS_SIGN_DSA_SHA1:
	case GNUTLS_SIGN_ECDSA_SHA1:
		return PKEY_HASH_SHA1;
	case GNUTLS_SIGN_RSA_MD5:
		return PKEY_HASH_MD5;
	case GNUTLS_SIGN_RSA_RMD160:
		return PKEY_HASH_RIPE_MD_160;
	case GNUTLS_SIGN_RSA_SHA256:
	case GNUTLS_SIGN_DSA_SHA256:
	case GNUTLS_SIGN_ECDSA_SHA256:
		return PKEY_HASH_SHA256;
	case GNUTLS_SIGN_RSA_SHA384:
	case GNUTLS_SIGN_ECDSA_SHA384:
	case GNUTLS_SIGN_DSA_SHA384:
		return PKEY_HASH_SHA384;
	case GNUTLS_SIGN_RSA_SHA512:
	case GNUTLS_SIGN_ECDSA_SHA512:
	case GNUTLS_SIGN_DSA_SHA512:
		return PKEY_HASH_SHA512;
	case GNUTLS_SIGN_RSA_SHA224:
	case GNUTLS_SIGN_DSA_SHA224:
	case GNUTLS_SIGN_ECDSA_SHA224:
		return PKEY_HASH_SHA224;
	default:
		return -1;
	}
	return -1;
}

/*
 * Extracts CN from O=Org,CN=CommonName,EMAIL=email
 */
static char *dn_str_to_cn(unsigned char *dn)
{
	char *s;
	char *e;
	char *r;
	size_t len;

	s = strstr((char *)dn, "CN=");
	if (s == NULL)
		return NULL;

	len = strlen(s);
	if (len < strlen("CN=") + 1) /* at least one symbol */
		return NULL;
	s += strlen("CN=");

	e = strchr(s, ',');
	if (e == NULL)
		e = s + len;
	len = e - s;

	r = malloc(len + 1);
	if (r == NULL)
		return NULL;

	memcpy(r, s, len);
	r[len] = '\0';
	return r;
}
static bool fill_pkcs7(const char *mem, off_t size,
		       const struct module_signature *modsig, size_t sig_len,
		       struct kmod_signature_info *sig_info)
{
	int rc;
	const char *pkcs7_raw;
	gnutls_pkcs7_t pkcs7;
	gnutls_datum_t data;
	gnutls_pkcs7_signature_info_st si;
	gnutls_x509_dn_t dn;
	struct pkcs7_private *pvt;
	char *issuer;

	size -= sig_len;
	pkcs7_raw = mem + size;

	rc = gnutls_pkcs7_init(&pkcs7);
	if (rc < 0)
		return false;

	data.data = (unsigned char *)pkcs7_raw;
	data.size = sig_len;
	rc = gnutls_pkcs7_import(pkcs7, &data, GNUTLS_X509_FMT_DER);
	if (rc < 0)
		goto err1;

	rc = gnutls_pkcs7_get_signature_info(pkcs7, 0, &si);
	if (rc < 0)
		goto err1;

	rc = gnutls_x509_dn_init(&dn);
	if (rc < 0)
		goto err2;

	rc = gnutls_x509_dn_import(dn, &si.issuer_dn);
	if (rc < 0)
		goto err3;

	/*
	 * I could not find simple wrapper to extract the data
	 * directly from ASN1, so get the string and parse it.
	 *
	 * Returns null-terminated string in data.data
	 */
	rc = gnutls_x509_dn_get_str(dn, &data);
	if (rc < 0)
		goto err3;

	sig_info->sig = (const char *)si.sig.data;
	sig_info->sig_len = si.sig.size;

	sig_info->key_id = (const char *)si.signer_serial.data;
	sig_info->key_id_len = si.signer_serial.size;

	issuer = dn_str_to_cn(data.data);
	if (issuer != NULL) {
		sig_info->signer = issuer;
		sig_info->signer_len = strlen(issuer);
	}

	sig_info->hash_algo = pkey_hash_algo_to_str(gnutls_algo_translate(si.algo));
	sig_info->id_type = pkey_id_type[modsig->id_type];

	pvt = malloc(sizeof(*pvt));
	if (pvt == NULL)
		goto err4;

	pvt->pkcs7 = pkcs7;
	pvt->si = si;
	pvt->dn = dn;
	pvt->dn_data = data;
	pvt->issuer = issuer;

	sig_info->private = pvt;
	sig_info->free = pkcs7_free;

	return true;

err4:
	gnutls_free(data.data);
err3:
	gnutls_x509_dn_deinit(dn);
err2:
	gnutls_pkcs7_signature_info_deinit(&si);
err1:
	gnutls_pkcs7_deinit(pkcs7);

	return false;
}

#else /* ENABLE GNUTLS */

static bool fill_pkcs7(const char *mem, off_t size,
		       const struct module_signature *modsig, size_t sig_len,
		       struct kmod_signature_info *sig_info)
{
	sig_info->hash_algo = "unknown";
	sig_info->id_type = pkey_id_type[modsig->id_type];
	return true;
}

#endif /* ENABLE GNUTLS */

#define SIG_MAGIC "~Module signature appended~\n"

/*
 * A signed module has the following layout:
 *
 * [ module                  ]
 * [ signer's name           ]
 * [ key identifier          ]
 * [ signature data          ]
 * [ struct module_signature ]
 * [ SIG_MAGIC               ]
 */

bool kmod_module_signature_info(const struct kmod_file *file, struct kmod_signature_info *sig_info)
{
	const char *mem;
	off_t size;
	const struct module_signature *modsig;
	size_t sig_len;

	size = kmod_file_get_size(file);
	mem = kmod_file_get_contents(file);
	if (size < (off_t)strlen(SIG_MAGIC))
		return false;
	size -= strlen(SIG_MAGIC);
	if (memcmp(SIG_MAGIC, mem + size, strlen(SIG_MAGIC)) != 0)
		return false;

	if (size < (off_t)sizeof(struct module_signature))
		return false;
	size -= sizeof(struct module_signature);
	modsig = (struct module_signature *)(mem + size);
	if (modsig->algo >= PKEY_ALGO__LAST ||
			modsig->hash >= PKEY_HASH__LAST ||
			modsig->id_type >= PKEY_ID_TYPE__LAST)
		return false;
	sig_len = be32toh(get_unaligned(&modsig->sig_len));
	if (sig_len == 0 ||
	    size < (int64_t)(modsig->signer_len + modsig->key_id_len + sig_len))
		return false;

	switch (modsig->id_type) {
	case PKEY_ID_PKCS7:
		return fill_pkcs7(mem, size, modsig, sig_len, sig_info);
	default:
		return fill_default(mem, size, modsig, sig_len, sig_info);
	}
}

void kmod_module_signature_info_free(struct kmod_signature_info *sig_info)
{
	if (sig_info->free)
		sig_info->free(sig_info);
}
