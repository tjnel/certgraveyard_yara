import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_DigiCert_65A52C21A339B9FA1AD1845EC5852DF {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-01"
      version             = "1.0"

      hash                = "668dcf124501c1767d4ebc19f29cb44d6474cbff28947d63a695628f467b6345"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Keroro Software LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "65:a5:2c:21:a3:39:b9:fa:1a:d1:84:5e:c5:85:2d:f"
      cert_thumbprint     = "6df54a199e246bc536fb12c4b99b3c5fd218a8a3"
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
         sig.serial == "65:a5:2c:21:a3:39:b9:fa:1a:d1:84:5e:c5:85:2d:f"
      )
}
