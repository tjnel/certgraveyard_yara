import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300004428428678F9C72CCD14000000004428 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-18"
      version             = "1.0"

      hash                = "a594109c34d1ce8b1be72b57d80bd696a7dbdf82186cb0789929a121f16db123"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Blanchard Nivell"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:44:28:42:86:78:f9:c7:2c:cd:14:00:00:00:00:44:28"
      cert_thumbprint     = "3202F38DC66D05469E1CEA62E0BDBD1B3CF3EB32"
      cert_valid_from     = "2026-04-18"
      cert_valid_to       = "2026-04-21"

      country             = "US"
      state               = "Texas"
      locality            = "SAN ANTONIO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:44:28:42:86:78:f9:c7:2c:cd:14:00:00:00:00:44:28"
      )
}
