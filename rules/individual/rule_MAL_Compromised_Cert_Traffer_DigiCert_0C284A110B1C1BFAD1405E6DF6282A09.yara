import "pe"

rule MAL_Compromised_Cert_Traffer_DigiCert_0C284A110B1C1BFAD1405E6DF6282A09 {
   meta:
      description         = "Detects Traffer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-17"
      version             = "1.0"

      hash                = "bba07e615664530a55d45151d2ddb194d85d165eff17f723b2ca7fd0ae350c9d"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PARADIMORE Services, s.r.o."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0c:28:4a:11:0b:1c:1b:fa:d1:40:5e:6d:f6:28:2a:09"
      cert_thumbprint     = "A7D3978F42DFA746AEB74850172FE1AA9251FE2A"
      cert_valid_from     = "2026-02-17"
      cert_valid_to       = "2027-02-16"

      country             = "CZ"
      state               = "???"
      locality            = "Prague"
      email               = "???"
      rdn_serial_number   = "02244365"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0c:28:4a:11:0b:1c:1b:fa:d1:40:5e:6d:f6:28:2a:09"
      )
}
