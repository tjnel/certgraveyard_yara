import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000B74A0EAFF4538188D4EE00000000B74A {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-03"
      version             = "1.0"

      hash                = "560469da7632d5282c925b68a3cc2ce0d3d0c52b332d8340dd9c8588554193ac"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:b7:4a:0e:af:f4:53:81:88:d4:ee:00:00:00:00:b7:4a"
      cert_thumbprint     = "2C9BC6BDA57D3C3700FC59DC2C6EB88F2E16A905"
      cert_valid_from     = "2026-05-03"
      cert_valid_to       = "2026-05-06"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:b7:4a:0e:af:f4:53:81:88:d4:ee:00:00:00:00:b7:4a"
      )
}
