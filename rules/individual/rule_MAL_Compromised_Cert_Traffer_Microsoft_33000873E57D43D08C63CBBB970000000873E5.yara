import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_33000873E57D43D08C63CBBB970000000873E5 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-24"
      version             = "1.0"

      hash                = "6e44ac52d6fccd54bcd9e86f60ae8a17de58d69a1e0168042773c78ebd76e745"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:73:e5:7d:43:d0:8c:63:cb:bb:97:00:00:00:08:73:e5"
      cert_thumbprint     = "F1A776A6B3A772E8A6CB5A196C47928DE7056FF5"
      cert_valid_from     = "2026-03-24"
      cert_valid_to       = "2026-03-27"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:73:e5:7d:43:d0:8c:63:cb:bb:97:00:00:00:08:73:e5"
      )
}
