import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_71EC769262102D63E053D47269E7E635 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-22"
      version             = "1.0"

      hash                = "73ab77da60d7196bce61405c615f8cd03a3157abffaf4a2447bd79fb8082da9f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Code Blue Staffing Inc."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "71:ec:76:92:62:10:2d:63:e0:53:d4:72:69:e7:e6:35"
      cert_thumbprint     = "f41e02b45eb637079920a49a52187f17c0816c7e"
      cert_valid_from     = "2026-09-22"
      cert_valid_to       = "2027-09-22"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "71:ec:76:92:62:10:2d:63:e0:53:d4:72:69:e7:e6:35"
      )
}
