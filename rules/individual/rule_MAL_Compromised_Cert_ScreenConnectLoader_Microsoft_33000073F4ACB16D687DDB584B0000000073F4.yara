import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000073F4ACB16D687DDB584B0000000073F4 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-23"
      version             = "1.0"

      hash                = "2db81e3bbef7e22d38d61b2e2db69eb7ad9fb74c08b09d596922245ae1796e0d"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:73:f4:ac:b1:6d:68:7d:db:58:4b:00:00:00:00:73:f4"
      cert_thumbprint     = "C92104A668F30F93C969CDB32A022BC747C29DBD"
      cert_valid_from     = "2026-04-23"
      cert_valid_to       = "2026-04-26"

      country             = "US"
      state               = "Tennessee"
      locality            = "nashville"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:73:f4:ac:b1:6d:68:7d:db:58:4b:00:00:00:00:73:f4"
      )
}
