import "pe"

rule MAL_Compromised_Cert_TamperedChef_Certum_5C1A74171954558211ACB8ABC9E16EE {
   meta:
      description         = "Detects TamperedChef with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-27"
      version             = "1.0"

      hash                = "af74f8974df1bff1c938a6f8f585cc8b5f370c98d41e7c5f476a4abda3cbfa2e"
      malware             = "TamperedChef"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Net Sourcing Experts LLC"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5c:1a:74:17:19:54:55:82:11:ac:b8:ab:c9:e1:6e:e"
      cert_thumbprint     = "98c987e4871012eead71cb5f351ce4e2357d9688"
      cert_valid_from     = "2026-02-27"
      cert_valid_to       = "2027-02-27"

      country             = "UA"
      state               = "Kyiv"
      locality            = "Kyiv"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5c:1a:74:17:19:54:55:82:11:ac:b8:ab:c9:e1:6e:e"
      )
}
