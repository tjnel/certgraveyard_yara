import "pe"

rule MAL_Compromised_Cert_cloakguard_agent_SSL_com_414D426BD6F09FC60814AF48F5BB4942 {
   meta:
      description         = "Detects cloakguard-agent with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-24"
      version             = "1.0"

      hash                = "5e3372db2b25f1e1fda89dcffc574a15702670bc04243f78fa3aa6b35b2f6929"
      malware             = "cloakguard-agent"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Space Solar Technologies LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "41:4d:42:6b:d6:f0:9f:c6:08:14:af:48:f5:bb:49:42"
      cert_thumbprint     = "9A07108DEC7C9D67FC43187CFA7942B901800B76"
      cert_valid_from     = "2026-08-24"
      cert_valid_to       = "2027-08-24"

      country             = "US"
      state               = "California"
      locality            = "Chula Vista"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "41:4d:42:6b:d6:f0:9f:c6:08:14:af:48:f5:bb:49:42"
      )
}
