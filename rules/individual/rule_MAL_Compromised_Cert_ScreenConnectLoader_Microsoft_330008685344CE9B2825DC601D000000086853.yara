import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330008685344CE9B2825DC601D000000086853 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "c11cfc997c91a180307e5a4f8b2ec614efb8284df146e465c97e91186e5035b0"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Johnson Tredaytrin Keyshawn"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:68:53:44:ce:9b:28:25:dc:60:1d:00:00:00:08:68:53"
      cert_thumbprint     = "13507B501DB562A438C7E7ADE26AF51E52FCAB62"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2026-03-26"

      country             = "US"
      state               = "Texas"
      locality            = "Taylor"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:68:53:44:ce:9b:28:25:dc:60:1d:00:00:00:08:68:53"
      )
}
