import "pe"

rule MAL_Compromised_Cert_StatusLoader_Microsoft_330008530CF9A7AFB498F69EED00000008530C {
   meta:
      description         = "Detects StatusLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-18"
      version             = "1.0"

      hash                = "26ef05efae0d0d6f04302aacd9ccb8104a51bd87e61e9485375a0dcacafc135d"
      malware             = "StatusLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MATTHEW PIGG"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:53:0c:f9:a7:af:b4:98:f6:9e:ed:00:00:00:08:53:0c"
      cert_thumbprint     = "124125590C11A640CBA4E08750B015C75D7130AA"
      cert_valid_from     = "2026-03-18"
      cert_valid_to       = "2026-03-21"

      country             = "US"
      state               = "California"
      locality            = "RICHMOND"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:53:0c:f9:a7:af:b4:98:f6:9e:ed:00:00:00:08:53:0c"
      )
}
