/*
 * Modifications Copyright 2024 Fondazione LINKS.
 */

/*
 * Copyright (C) 2009 Martin Willi
 * Copyright (C) 2014-2016 Andreas Steffen
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

#include "pki.h"
#ifdef VC_AUTH
#include <credentials/dids/decentralized_identifier.h>
#include <credentials/vcs/verifiable_credential.h>
#endif

/**
 * Generate a private key
 */
static int gen()
{
	cred_encoding_type_t form = PRIVKEY_ASN1_DER;
	key_type_t type = KEY_RSA;
#ifdef VC_AUTH
	decentralized_identifier_type_t did_type;
	verifiable_credential_type_t vc_type;
	bool vc_gen = FALSE;
	decentralized_identifier_t *did;
	verifiable_credential_t *vc;
#endif
	u_int size = 0, shares = 0, threshold = 1;
	private_key_t *key;
	chunk_t encoding;
	bool safe_primes = FALSE;
	char *arg;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 't':
				if (streq(arg, "rsa"))
				{
					type = KEY_RSA;
				}
				else if (streq(arg, "ecdsa"))
				{
					type = KEY_ECDSA;
				}
				else if (streq(arg, "ed25519"))
				{
					type = KEY_ED25519;
				}
				else if (streq(arg, "ed448"))
				{
					type = KEY_ED448;
				}
				else if (streq(arg, "bliss"))
				{
					type = KEY_BLISS;
				}
#ifdef VC_AUTH
				else if (streq(arg, "iota"))
				{
					did_type = DID_IOTA;
					vc_type = VC_DATA_MODEL_2_0;
					vc_gen = TRUE;
				}
#endif
				else
				{
					return command_usage("invalid key type");
				}
				continue;
			case 'f':
				if (!get_form(arg, &form, CRED_PRIVATE_KEY))
				{
					return command_usage("invalid key output format");
				}
				continue;
			case 's':
				size = atoi(arg);
				if (!size)
				{
					return command_usage("invalid key size");
				}
				continue;
			case 'p':
				safe_primes = TRUE;
				continue;
			case 'n':
				shares = atoi(arg);
				if (shares < 2)
				{
					return command_usage("invalid number of key shares");
				}
				continue;
			case 'l':
				threshold = atoi(arg);
				if (threshold < 1)
				{
					return command_usage("invalid key share threshold");
				}
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --gen option");
		}
		break;
	}
	/* default key sizes */
	if (!size)
	{
		switch (type)
		{
			case KEY_RSA:
				size = 2048;
				break;
			case KEY_ECDSA:
				size = 384;
				break;
			case KEY_ED25519:
				size = 256;
				break;
			case KEY_ED448:
				size = 456;
				break;
			case KEY_BLISS:
				size = 1;
				break;
			default:
				break;
		}
	}
#ifdef VC_AUTH
	if (vc_gen == TRUE && did_type == DID_IOTA) 
	{	
		chunk_t did_encoding;
		chunk_t vc_encoding;
		did = lib->creds->create(lib->creds, CRED_DECENTRALIZED_IDENTIFIER, did_type, BUILD_END);
		if(!did)
		{
			fprintf(stderr, "did document generation failed\n");
			return 1;
		}

		if(!did->get_encoding(did, DID_ASN1_DER, &did_encoding))
		{
			fprintf(stderr, "did document encoding failed\n");
			did->destroy(did);
			return 1;
		}

		vc = lib->creds->create(lib->creds, CRED_VERIFIABLE_CREDENTIAL, vc_type, BUILD_VC_CREATE, did_encoding, BUILD_END);
		if(!vc)
		{
			fprintf(stderr, "verifiable credential generation failed\n");
			return 1;
		}

		chunk_clear(&did_encoding);
		if(!did->get_encoding(did, DID_PEM, &did_encoding))
		{
			fprintf(stderr, "did document PEM encoding failed\n");
			did->destroy(did);
			return 1;
		}
		//did->destroy(did);
		/* All the stdout content gets redirected to the file that contains the DID */
		set_file_mode(stdout, DID_PEM);
		if (fwrite(did_encoding.ptr, did_encoding.len, 1, stdout) != 1)
		{
			fprintf(stderr, "writing DID document failed\n");
			free(did_encoding.ptr);
			return 1;
		}
		free(did_encoding.ptr);

		if(!vc->get_encoding(vc, VC_PEM, &vc_encoding))
		{
			fprintf(stderr, "VC PEM encoding failed\n");
			vc->destroy(vc);
			return 1;
		}
		//vc->destroy(vc);
		/* All the stderr content gets redirected to the file that contains the VC */
		set_file_mode(stderr, VC_PEM);
		if (fwrite(vc_encoding.ptr, vc_encoding.len, 1, stderr) != 1)
		{
			fprintf(stderr, "writing VC document failed\n");
			free(vc_encoding.ptr);
			return 1;
		}
		free(vc_encoding.ptr);
		
		return 0;
	}
#endif
	if (type == KEY_RSA && shares)
	{
		if (threshold > shares)
		{
			return command_usage("threshold is larger than number of shares");
		}
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
							BUILD_KEY_SIZE, size, BUILD_SAFE_PRIMES,
							BUILD_SHARES, shares, BUILD_THRESHOLD, threshold,
							BUILD_END);
	}
	else if (type == KEY_RSA && safe_primes)
	{
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
							BUILD_KEY_SIZE, size, BUILD_SAFE_PRIMES, BUILD_END);
	}
	else
	{
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
							BUILD_KEY_SIZE, size, BUILD_END);
	}
	if (!key)
	{
		fprintf(stderr, "private key generation failed\n");
		return 1;
	}
	if (!key->get_encoding(key, form, &encoding))
	{
		fprintf(stderr, "private key encoding failed\n");
		key->destroy(key);
		return 1;
	}
	key->destroy(key);
	set_file_mode(stdout, form);
	if (fwrite(encoding.ptr, encoding.len, 1, stdout) != 1)
	{
		fprintf(stderr, "writing private key failed\n");
		free(encoding.ptr);
		return 1;
	}
	free(encoding.ptr);
	return 0;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		gen, 'g', "gen", "generate a new private key",
		{"[--type rsa|ecdsa|ed25519|ed448|bliss] [--size bits] [--safe-primes]",
		 "[--shares n] [--threshold l] [--outform der|pem]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"type",		't', 1, "type of key, default: rsa"},
			{"size",		's', 1, "keylength in bits, default: rsa 2048, ecdsa 384, bliss 1"},
			{"safe-primes", 'p', 0, "generate rsa safe primes"},
			{"shares",		'n', 1, "number of private rsa key shares"},
			{"threshold",	'l', 1, "minimum number of participating rsa key shares"},
			{"outform",		'f', 1, "encoding of generated private key, default: der"},
		}
	});
}
