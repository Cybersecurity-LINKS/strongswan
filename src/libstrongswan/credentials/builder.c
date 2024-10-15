/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2016-2023 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "builder.h"

ENUM(builder_part_names, BUILD_FROM_FILE, BUILD_END,
	"BUILD_FROM_FILE",
	"BUILD_AGENT_SOCKET",
	"BUILD_BLOB",
	"BUILD_BLOB_ASN1_DER",
	"BUILD_BLOB_PEM",
	"BUILD_BLOB_PGP",
	"BUILD_BLOB_DNSKEY",
	"BUILD_BLOB_SSHKEY",
	"BUILD_BLOB_ALGID_PARAMS",
	"BUILD_KEY_SIZE",
	"BUILD_SIGNING_KEY",
	"BUILD_SIGNING_CERT",
	"BUILD_PUBLIC_KEY",
	"BUILD_SUBJECT",
	"BUILD_SUBJECT_ALTNAMES",
	"BUILD_ISSUER",
	"BUILD_ISSUER_ALTNAMES",
	"BUILD_NOT_BEFORE_TIME",
	"BUILD_NOT_AFTER_TIME",
	"BUILD_SERIAL",
	"BUILD_SIGNATURE_SCHEME",
	"BUILD_DIGEST_ALG",
	"BUILD_ENCRYPTION_ALG",
	"BUILD_AC_GROUP_STRINGS",
	"BUILD_CA_CERT",
	"BUILD_CERT",
	"BUILD_CRL_DISTRIBUTION_POINTS",
	"BUILD_OCSP_ACCESS_LOCATIONS",
#ifdef VC_AUTH
	"BUILD_VC_VERIFY",
#endif
	"BUILD_PATHLEN",
	"BUILD_ADDRBLOCKS",
	"BUILD_PERMITTED_NAME_CONSTRAINTS",
	"BUILD_EXCLUDED_NAME_CONSTRAINTS",
	"BUILD_CERTIFICATE_POLICIES",
	"BUILD_POLICY_MAPPINGS",
	"BUILD_POLICY_REQUIRE_EXPLICIT",
	"BUILD_POLICY_INHIBIT_MAPPING",
	"BUILD_POLICY_INHIBIT_ANY",
	"BUILD_X509_FLAG",
	"BUILD_REVOKED_ENUMERATOR",
	"BUILD_BASE_CRL",
	"BUILD_CHALLENGE_PWD",
	"BUILD_CERT_TYPE_EXT",
	"BUILD_PKCS7_ATTRIBUTE",
	"BUILD_PKCS11_MODULE",
	"BUILD_PKCS11_SLOT",
	"BUILD_PKCS11_KEYID",
	"BUILD_RSA_MODULUS",
	"BUILD_RSA_PUB_EXP",
	"BUILD_RSA_PRIV_EXP",
	"BUILD_RSA_PRIME1",
	"BUILD_RSA_PRIME2",
	"BUILD_RSA_EXP1",
	"BUILD_RSA_EXP2",
	"BUILD_RSA_COEFF",
	"BUILD_SAFE_PRIMES",
	"BUILD_SHARES",
	"BUILD_THRESHOLD",
	"BUILD_EDDSA_PUB",
	"BUILD_EDDSA_PRIV_ASN1_DER",
	"BUILD_CRITICAL_EXTENSION",
	"BUILD_NONCE",
	"BUILD_OCSP_STATUS",
	"BUILD_OCSP_RESPONSES",
	"BUILD_END",
);
