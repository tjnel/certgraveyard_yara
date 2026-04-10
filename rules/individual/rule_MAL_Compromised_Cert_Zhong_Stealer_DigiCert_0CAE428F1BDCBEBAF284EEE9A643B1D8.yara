import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_0CAE428F1BDCBEBAF284EEE9A643B1D8 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "9ae8388b6bc4043a49573a617927cabbd61c254014e0ceb4223cf50431841b2c"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "Brunner Informatik AG"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0c:ae:42:8f:1b:dc:be:ba:f2:84:ee:e9:a6:43:b1:d8"
      cert_thumbprint     = "EC4960102B57FD7966DEAB52AA97A8F33223A430"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-07-10"

      country             = "CH"
      state               = "Bern"
      locality            = "Ittigen"
      email               = "???"
      rdn_serial_number   = "CHE-103.742.564"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0c:ae:42:8f:1b:dc:be:ba:f2:84:ee:e9:a6:43:b1:d8"
      )
}
