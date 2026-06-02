import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000068EB6233BBCBA1C5390A0000000068EB {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-22"
      version             = "1.0"

      hash                = "a4a2b849bee2f077985590a8127d9f0ebd64c067371c32585e2553d0628ce039"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Avery Benavidez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:68:eb:62:33:bb:cb:a1:c5:39:0a:00:00:00:00:68:eb"
      cert_thumbprint     = "EE2C1D2A3B3E06BE9EAB53463694745D9488062D"
      cert_valid_from     = "2026-04-22"
      cert_valid_to       = "2026-04-25"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:68:eb:62:33:bb:cb:a1:c5:39:0a:00:00:00:00:68:eb"
      )
}
