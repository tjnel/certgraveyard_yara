import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_1BDC9C2C1A1922C5A71C2575CF61317 {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-08"
      version             = "1.0"

      hash                = "ba3d3301734d31d36ff25bbe2ada1180fc4357c03b9cba21d3e18445b76b6f7e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Monarch Innovation Private Limited"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "1b:dc:9c:2c:1a:19:22:c5:a7:1c:25:75:cf:61:31:7"
      cert_thumbprint     = "3ba886534b93aeba82132e4056f96a2310a663c7"
      cert_valid_from     = "2026-07-08"
      cert_valid_to       = "2027-07-07"

      country             = "IN"
      state               = "Gujarat"
      locality            = "Ahmedabad"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "1b:dc:9c:2c:1a:19:22:c5:a7:1c:25:75:cf:61:31:7"
      )
}
