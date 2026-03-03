import "pe"

rule MAL_Compromised_Cert_FakeDocument_DigiCert_0FA698D92B3420800CFD2C72E766AE53 {
   meta:
      description         = "Detects FakeDocument with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-20"
      version             = "1.0"

      hash                = "89295ba81f3008c6ab03fdd77dc4a75a0920f708fb4e09c156c077b4dfedd0ec"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CYBERWHIZ SIBER GUVENLIK ANONIM SIRKETI"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0f:a6:98:d9:2b:34:20:80:0c:fd:2c:72:e7:66:ae:53"
      cert_thumbprint     = "0EDBF2819738DFDF6160D64B9FF4D8EBDD059133"
      cert_valid_from     = "2026-02-20"
      cert_valid_to       = "2027-02-19"

      country             = "TR"
      state               = "İstanbul"
      locality            = "Şişli"
      email               = "???"
      rdn_serial_number   = "1026249"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0f:a6:98:d9:2b:34:20:80:0c:fd:2c:72:e7:66:ae:53"
      )
}
