## Purpose

This is a fork of strongSwan to support VC authentication in the IKE protocol. We designed and implemented the `vc_iota` plugin that employs the [identity-cbindings](https://github.com/Cybersecurity-LINKS/identity-cbindings) to generate VCs through the IOTA Identity library. Anyane can design and implement their own VC plugin compliant to the SSI library they prefer.

The original `README` can be found at [README-STRONGSWAN](README-STRONGSWAN.md)

## Modifications

A brief description of added and modified files can be found at [MODIFICATIONS](MODIFICATIONS.md).

## Build

We added the `vc-iota` plugin in the `configure.ac` file to support VC authentication in IKEv2. The option is disabled by default, so when you run the `configure` script you need to add the option `--enable-vc-iota`

## Usage

We provide an example of VC generation and `swanctl.file` configuration files in a Roadwarrior case scenario with a gateway and a client

### client

    pki --gen --type iota --outform pem > client_did_document.pem 2> client_vc.pem

Then copy them in the `swanctl/etc` dir

    cp client_vc.pem path/to/strongswan/etc/swanctl/vc
    cp client_did_document.pem path/to/strongswan/etc/swanctl/iota

The `swanctl.conf` file

connections {
  home {
    remote_addrs = gateway.org
    local {
      auth = pubkey
      vcs = client_vc.pem
      id = client.org
    }
    remote {
      auth = pubkey
      id = gateway.org
    }
    children {
      home {
        remote_ts  = 10.10.10.0/24
        start_action = start
      }
    }
    send_certreq = no
    send_vcreq = yes
  }
}

### gateway

    pki --gen --type iota --outform pem > gateway_did_document.pem 2> gateway_vc.pem

Then copy them in the `swanctl/etc` dir

    cp gateway_vc.pem path/to/strongswan/etc/swanctl/vc
    cp gateway_did_document.pem path/to/strongswan/etc/swanctl/iota

The `swanctl.conf` file

connections {
    rw {
      local {
        auth = pubkey
        vcs = gateway_vc.pem
        id = gateway.org
      }
      remote {
        auth = pubkey
      }
      children {
        rw {
          local_ts  = 10.10.10.0/24
        }
      }
      send_certreq = no
      send_vcreq = yes
    }
  }


