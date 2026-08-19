import "pe"

rule MAL_Compromised_Cert_OneStart_DigiCert_333EAFBA707AABFD12644AEDC2E8C4E {
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
      cert_serial         = "33:3e:af:ba:70:7a:ab:fd:12:64:4a:ed:c2:e8:c4:e"
      cert_thumbprint     = "bcbaa4f693051d69280d19d69de73832b77b1c25"
      cert_valid_from     = "2025-06-10"
      cert_valid_to       = "2026-06-09"

      country             = "US"
      state               = "Delaware"
      locality            = "Dover"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "33:3e:af:ba:70:7a:ab:fd:12:64:4a:ed:c2:e8:c4:e"
      )
}
