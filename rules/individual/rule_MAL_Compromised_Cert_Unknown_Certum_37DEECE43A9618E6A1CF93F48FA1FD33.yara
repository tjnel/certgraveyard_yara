import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_37DEECE43A9618E6A1CF93F48FA1FD33 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-16"
      version             = "1.0"

      hash                = "fd116eb7e791b809fef261b970b02fcda4a7488ff31f58f381a1e4d1f498a504"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "REDPOINT SOFTWARE ANS"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "37:de:ec:e4:3a:96:18:e6:a1:cf:93:f4:8f:a1:fd:33"
      cert_thumbprint     = "77C1D3EA609206CE0E749FE5C629B0C33A0D884C"
      cert_valid_from     = "2026-04-16"
      cert_valid_to       = "2027-04-16"

      country             = "NO"
      state               = "Trøndelag"
      locality            = "Klæbu"
      email               = "???"
      rdn_serial_number   = "989538020"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "37:de:ec:e4:3a:96:18:e6:a1:cf:93:f4:8f:a1:fd:33"
      )
}
