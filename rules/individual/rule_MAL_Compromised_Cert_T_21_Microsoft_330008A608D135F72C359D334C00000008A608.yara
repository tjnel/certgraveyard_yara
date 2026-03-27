import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330008A608D135F72C359D334C00000008A608 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "4982be70eacad774c6a37281982a8ee05606d6d624d6949954253124ff4f9bee"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex targeting crypto users worldwide"

      signer              = "PIERRE MARC J D JANNOT"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:a6:08:d1:35:f7:2c:35:9d:33:4c:00:00:00:08:a6:08"
      cert_thumbprint     = "52581B2C9F65D2D86D81B194780AC436DDE14280"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2026-03-26"

      country             = "US"
      state               = "California"
      locality            = "LOS ANGELES"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:a6:08:d1:35:f7:2c:35:9d:33:4c:00:00:00:08:a6:08"
      )
}
