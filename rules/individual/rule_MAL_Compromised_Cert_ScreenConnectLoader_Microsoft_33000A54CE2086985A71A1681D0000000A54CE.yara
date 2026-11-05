import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000A54CE2086985A71A1681D0000000A54CE {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-01"
      version             = "1.0"

      hash                = "61e6fe15b423177661294e31bf32f9112bfb531a71a79327eb8dbc732278e8c1"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ITTC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:0a:54:ce:20:86:98:5a:71:a1:68:1d:00:00:00:0a:54:ce"
      cert_thumbprint     = "99ee47f4e5f3edfda534fa5626c38c800cddb1cd"
      cert_valid_from     = "2026-11-01"
      cert_valid_to       = "2026-11-04"

      country             = "NL"
      state               = "Utrecht"
      locality            = "Urecht"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:0a:54:ce:20:86:98:5a:71:a1:68:1d:00:00:00:0a:54:ce"
      )
}
