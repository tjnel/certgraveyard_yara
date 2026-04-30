import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_330006775D9BB106BEC33FA81800000006775D {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-28"
      version             = "1.0"

      hash                = "d3204724a4519d0609b1b9831083c6c7cdd931d9b04dbf4d013d67e166222d7c"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:77:5d:9b:b1:06:be:c3:3f:a8:18:00:00:00:06:77:5d"
      cert_thumbprint     = "E6E8FD22544A9159044B4B92E085158E252C4A6D"
      cert_valid_from     = "2025-11-28"
      cert_valid_to       = "2025-12-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:77:5d:9b:b1:06:be:c3:3f:a8:18:00:00:00:06:77:5d"
      )
}
