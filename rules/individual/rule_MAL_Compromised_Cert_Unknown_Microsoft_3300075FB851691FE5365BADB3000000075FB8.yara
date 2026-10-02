import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_3300075FB851691FE5365BADB3000000075FB8 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-29"
      version             = "1.0"

      hash                = "b25c9e7e793a86965779a71a8e8f81a2d43f40db54b7c252768faff306071fd6"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Essie Sound"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:07:5f:b8:51:69:1f:e5:36:5b:ad:b3:00:00:00:07:5f:b8"
      cert_thumbprint     = "fdacbf8afbbb8d860cd10eceb0b987dbb49b06af"
      cert_valid_from     = "2026-09-29"
      cert_valid_to       = "2026-10-02"

      country             = "NL"
      state               = "Friesland"
      locality            = "Heerenveen"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:07:5f:b8:51:69:1f:e5:36:5b:ad:b3:00:00:00:07:5f:b8"
      )
}
