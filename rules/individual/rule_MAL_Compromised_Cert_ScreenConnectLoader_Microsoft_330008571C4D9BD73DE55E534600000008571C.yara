import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330008571C4D9BD73DE55E534600000008571C {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "06a29c82cf8cdafab4f3f4feb1d4946db660da95f0faebcf1925deaec7faba5d"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Johnson Tredaytrin Keyshawn"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:57:1c:4d:9b:d7:3d:e5:5e:53:46:00:00:00:08:57:1c"
      cert_thumbprint     = "AD970CA9D0B0C9FAE560739C512289D7FBB5C2A4"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2026-03-22"

      country             = "US"
      state               = "Texas"
      locality            = "Taylor"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:57:1c:4d:9b:d7:3d:e5:5e:53:46:00:00:00:08:57:1c"
      )
}
