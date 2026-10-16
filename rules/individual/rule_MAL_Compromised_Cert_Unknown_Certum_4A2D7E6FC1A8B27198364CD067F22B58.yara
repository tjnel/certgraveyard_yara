import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_4A2D7E6FC1A8B27198364CD067F22B58 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-18"
      version             = "1.0"

      hash                = "9b43bb4e22b438ef28ea41f29c755d71a825950c70a11fa9c569dd02bca91129"
      malware             = "Unknown"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "SOFTWARE DYNAMICS AS"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4a:2d:7e:6f:c1:a8:b2:71:98:36:4c:d0:67:f2:2b:58"
      cert_thumbprint     = "eb98fddcd2c03d47f861e379538373f7d9f0d6be"
      cert_valid_from     = "2026-03-18"
      cert_valid_to       = "2027-03-18"

      country             = "NO"
      state               = "Trøndelag"
      locality            = "Inderøy"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4a:2d:7e:6f:c1:a8:b2:71:98:36:4c:d0:67:f2:2b:58"
      )
}
