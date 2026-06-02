import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001679C0711E6A6714F3DBD00000001679C {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-28"
      version             = "1.0"

      hash                = "b5d8d81fe4264d9b32a8a9c148ff342e4583d62a2b4bd6781a01145669babd38"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sabrina Perry"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:01:67:9c:07:11:e6:a6:71:4f:3d:bd:00:00:00:01:67:9c"
      cert_thumbprint     = "6DEE979BB5D8B181343965DAF5D5E68A33EBBFC1"
      cert_valid_from     = "2026-05-28"
      cert_valid_to       = "2026-05-31"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:01:67:9c:07:11:e6:a6:71:4f:3d:bd:00:00:00:01:67:9c"
      )
}
