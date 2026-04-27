import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300006C03E05B593A61954D42000000006C03 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-22"
      version             = "1.0"

      hash                = "39966799de10438c2e7c0050b53f0f2943a1ca99507e9a1e171e9c3db74e7670"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Perry Sabrina Ann"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:6c:03:e0:5b:59:3a:61:95:4d:42:00:00:00:00:6c:03"
      cert_thumbprint     = "73874BEFAF2348DCE7255B52A91E127FAA1CB5EF"
      cert_valid_from     = "2026-04-22"
      cert_valid_to       = "2026-04-25"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:6c:03:e0:5b:59:3a:61:95:4d:42:00:00:00:00:6c:03"
      )
}
