import "pe"

rule MAL_Compromised_Cert_StatusLoader_DigiCert_08F03A563241B64D3A7A5C6AA5CF2D8E {
   meta:
      description         = "Detects StatusLoader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-12"
      version             = "1.0"

      hash                = "5e9378f72e5f96e0215390c8f44e4b2e0445a09ebe8781c6e5d9cb512129cda3"
      malware             = "StatusLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PRONTO STAVBA s.r.o."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "08:f0:3a:56:32:41:b6:4d:3a:7a:5c:6a:a5:cf:2d:8e"
      cert_thumbprint     = "1B2A579D453B84247688324B67B35938019FE087"
      cert_valid_from     = "2026-03-12"
      cert_valid_to       = "2027-03-11"

      country             = "CZ"
      state               = "???"
      locality            = "Ostrava"
      email               = "???"
      rdn_serial_number   = "26786761"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "08:f0:3a:56:32:41:b6:4d:3a:7a:5c:6a:a5:cf:2d:8e"
      )
}
