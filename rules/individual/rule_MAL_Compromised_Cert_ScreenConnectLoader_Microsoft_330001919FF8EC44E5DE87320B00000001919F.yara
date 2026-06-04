import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001919FF8EC44E5DE87320B00000001919F {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-31"
      version             = "1.0"

      hash                = "de551de5d6e0f9d7bcf4b72312449eb57ca33aa3c43ecd0219721a104431d00f"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Danielle Hale"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:91:9f:f8:ec:44:e5:de:87:32:0b:00:00:00:01:91:9f"
      cert_thumbprint     = "CF545B86807A346F88C5EF9EAC43C3F9FF20EA9C"
      cert_valid_from     = "2026-05-31"
      cert_valid_to       = "2026-06-03"

      country             = "US"
      state               = "oh"
      locality            = "Cleveland"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:91:9f:f8:ec:44:e5:de:87:32:0b:00:00:00:01:91:9f"
      )
}
