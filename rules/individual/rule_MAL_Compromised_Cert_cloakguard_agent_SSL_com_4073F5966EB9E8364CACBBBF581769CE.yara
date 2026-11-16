import "pe"

rule MAL_Compromised_Cert_cloakguard_agent_SSL_com_4073F5966EB9E8364CACBBBF581769CE {
   meta:
      description         = "Detects cloakguard-agent with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-10"
      version             = "1.0"

      hash                = "79b95926932d3749990e2d33057f800bd44870c9f9ce3ca2a16809a1286b1578"
      malware             = "cloakguard-agent"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Admintecho LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "40:73:f5:96:6e:b9:e8:36:4c:ac:bb:bf:58:17:69:ce"
      cert_thumbprint     = "437da53100803a114aa15ca52eb9ade85948f086"
      cert_valid_from     = "2026-09-10"
      cert_valid_to       = "2027-09-10"

      country             = "US"
      state               = "Virginia"
      locality            = "Newport News"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "40:73:f5:96:6e:b9:e8:36:4c:ac:bb:bf:58:17:69:ce"
      )
}
