import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001D1FC7AD23F039C2FD47F00000001D1FC {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-07"
      version             = "1.0"

      hash                = "d65e62c2b216b577d6a532f8dd0e301875bf61abe6a6f4e28195baa82953d2dc"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "David Shiffer"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:d1:fc:7a:d2:3f:03:9c:2f:d4:7f:00:00:00:01:d1:fc"
      cert_thumbprint     = "679DD06C07C0DD04A78A6EF0168AE8E46743A392"
      cert_valid_from     = "2026-06-07"
      cert_valid_to       = "2026-06-10"

      country             = "US"
      state               = "tx"
      locality            = "Georgetown"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:d1:fc:7a:d2:3f:03:9c:2f:d4:7f:00:00:00:01:d1:fc"
      )
}
