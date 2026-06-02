import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001133FCF9D196F711DACCF00000001133F {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-15"
      version             = "1.0"

      hash                = "c896efb44e5373135057d13d6c77bba1342bc509b3774faec6c6f8faa6709c28"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Morrison Chaunesey"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:13:3f:cf:9d:19:6f:71:1d:ac:cf:00:00:00:01:13:3f"
      cert_thumbprint     = "48FC2B7F4FDE6588E3E968A86A36BDE322D80913"
      cert_valid_from     = "2026-05-15"
      cert_valid_to       = "2026-05-18"

      country             = "US"
      state               = "Texas"
      locality            = "Converse"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:13:3f:cf:9d:19:6f:71:1d:ac:cf:00:00:00:01:13:3f"
      )
}
