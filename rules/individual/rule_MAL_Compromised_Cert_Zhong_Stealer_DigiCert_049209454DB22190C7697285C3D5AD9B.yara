import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_049209454DB22190C7697285C3D5AD9B {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-10"
      version             = "1.0"

      hash                = "c918dded298b0d76d4ac51f23b391f62a95f58b3fa2488202ecbbc9c7ce8e785"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "DigiFors GmbH"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA256 2021 CA1"
      cert_serial         = "04:92:09:45:4d:b2:21:90:c7:69:72:85:c3:d5:ad:9b"
      cert_thumbprint     = "77945AAE69E08A7DBF173ED45F857CF79BA36B04"
      cert_valid_from     = "2026-04-10"
      cert_valid_to       = "2027-04-09"

      country             = "DE"
      state               = "Sachsen"
      locality            = "Leipzig"
      email               = "???"
      rdn_serial_number   = "HRB 26934"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA256 2021 CA1" and
         sig.serial == "04:92:09:45:4d:b2:21:90:c7:69:72:85:c3:d5:ad:9b"
      )
}
