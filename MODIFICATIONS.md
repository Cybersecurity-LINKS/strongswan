### swantcl

- **commands**
	-  `load_creds.c`: `load_vc()` and `load_did()` through `swanctl`
- `swanctl.h`: add vc and did directories to store VCs and DIDs

### libstrongswan

- **credentials/**
	- `credential_manager.h/.c`:  added create_vc_enumerator, and did_public_enumerator and get_did_private.  
	- `credential_set.h`: added `create_vc_enumerator()` and create_did_enumerator(). The credentials_set interface is implemented by all the files in the `sets` directory.
	- `builder.h/.c`: added `BUILD_VC_CREATE` and `BUILD_VC_VERIFY`.
	- `cred_encoding.h`: added DID and VC cred encoding
	- `credential_factory.h`: `CRED_VERIFIABLE_CREDENTIAL` and `CRED_DECENTRALIZED_IDENTIFIER` credential types
	- `credential_factory.c`: the create method iterates over CRED_VERIFIABLE_CREDENTIAL and CRED_DECENTRALIZED_IDENTIFIER
	- `auth_cfg.h/.c`: added VC authentication rule

- **sets/**
	- `auth_cfg_wrapper.c`: added a vc_enumerator to enumerate over peer VCs to check the AUTH
	- `callback_cred.c`: null pointer to create_did_private_enumerator and create_vc_enumerator()   
	- `cert_cache.c`: null pointer to `create_did_private_enumerator()` and `create_vc_enumerator()` 
	- `mem_cred.h`: `add_vc()`, `add_vc_ref()` and `get_vc_ref()`
	- `mem_cred.c`: `create_vc_enumerator()` and `create_did_private_enumerator()`  
	- `ocsp_response_wrapper.c`: null pointer to `create_did_private_enumerator()` and `create_vc_enumerator()`

- **vcs/**
	- `verifiable_credential.h/.c`: created the interface for the VC credential that will be implemented by the `vc_iota` plugin.

- **dids/**
	- `decentralized_identifier.h/.c:` created the interface for the DID credential that will be implemented in the `vc_iota` plugin by `did_iota.h/.c`. 

- **plugins/**
	- `plugin_feature.h/c`: added the VC and DID plugin features.
	- **vc_iota/**
		- `vc_iota.h/.c`: implements the `verifiable_credential_t` interface according to IOTA identity
		- `did_iota.h/.c`: implements the `decentralized_identifier_t` interface according to IOTA identity  
		- `vc_iota_plugin.h/.c`: 
		- identity.h: identity-cbindings interface
	- **pem/**
		- `pem_encoder.c/h`: added encoding of VC and DID to the `pem_encoder_encode()` method 
		- `pem_builder.c/h`: add pem_vc_load() and did_pem_load() to parse the PEM file when loading credentials.
		- `pem_plugin.c`: added VC and DID features

### libcharon

- **plugins/**
	- **vici/**
		- `vici_cred.c/.h`: load_vc and load_did to create the VC and DID credentials and add them to the credential manager.
		- `vici_config.c`: I made additions to load the VC configuration from the swanctl.conf
		- `vici_authority.c`: null pointer to `create_did_private_enumerator()` and `create_vc_enumerator()`
- **sa/**
	- `ike_sa.h`: add `COND_VCREQ_SEEN`
	- **ikev2/**
		- **authenticators/**
			- `pubkey_authenticator.c`: `sign_did()` to sign the AUTH payload with the DID privateky.
		- **tasks/**
			- `ike_cert_pre.c`: functions that build and process the CERTREQ payload with VC and creates the CERT payload with VC
			- `ike_cert_post.c`: functions that build CERT payload with VC.
			- `ike_establish.c`: add time functions
			- `ike_init`: add time functions
- **encoding/payloads/**
	- `cert_payload.h/.c`: creates the CERT payload with VC.
	- `certreq_payload.h/.c`: creates the CERTREQ payload with VC
- **config/**
	- `peer_cfg.c/.h`: added vc_policy for sending the VC
	- `ike_cfg.h/.c`: send vc_certreq

### pki

- **commands/**
	- `gen.c`: added the option and functions< to generate a VC and DID document
- `pki.c`: DID and VC encoding