import "pe"

rule MAL_Compromised_Cert_OneStart_DigiCert_0333EAFBA707AABFD12644AEDC2E8C4E {
   meta:
      description         = "Detects OneStart with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-10"
      version             = "1.0"

      hash                = "065b386addf06337ad1d40f7b05cbb137c6c4ee7589c1ea22e4e18c0cefe850c"
      malware             = "OneStart"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OneStart Technologies LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "03:33:ea:fb:a7:07:aa:bf:d1:26:44:ae:dc:2e:8c:4e"
      cert_thumbprint     = "BCBAA4F693051D69280D19D69DE73832B77B1C25"
      cert_valid_from     = "2025-06-10"
      cert_valid_to       = "2026-06-09"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "03:33:ea:fb:a7:07:aa:bf:d1:26:44:ae:dc:2e:8c:4e"
      )
}
