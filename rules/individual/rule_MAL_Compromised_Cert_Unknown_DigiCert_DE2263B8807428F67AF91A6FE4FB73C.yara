import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_DE2263B8807428F67AF91A6FE4FB73C {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-01"
      version             = "1.0"

      hash                = "bed33b976e89aaefbde6e66304f01855505620ccb86876c0f001a8a192a647dc"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Keroro Software LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "de:22:63:b8:80:74:28:f6:7a:f9:1a:6f:e4:fb:73:c"
      cert_thumbprint     = "0b543a3e96bfe6fb6e9b41fab76f312ebfb20883"
      cert_valid_from     = "2025-07-01"
      cert_valid_to       = "2028-09-26"

      country             = "CN"
      state               = "广东省"
      locality            = "深圳市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "de:22:63:b8:80:74:28:f6:7a:f9:1a:6f:e4:fb:73:c"
      )
}
