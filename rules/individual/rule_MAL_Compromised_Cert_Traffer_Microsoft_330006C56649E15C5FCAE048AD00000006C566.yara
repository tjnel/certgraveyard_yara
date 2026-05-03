import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_330006C56649E15C5FCAE048AD00000006C566 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-04"
      version             = "1.0"

      hash                = "4d7f1aa56d46ba6b94ab0fc6007cba67561d7be96687bfb18264cbc4d3d3fa6b"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:c5:66:49:e1:5c:5f:ca:e0:48:ad:00:00:00:06:c5:66"
      cert_thumbprint     = "E4A5CEFE56DE01654DD43D5DB32631B9B66794BC"
      cert_valid_from     = "2026-01-04"
      cert_valid_to       = "2026-01-07"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:c5:66:49:e1:5c:5f:ca:e0:48:ad:00:00:00:06:c5:66"
      )
}
