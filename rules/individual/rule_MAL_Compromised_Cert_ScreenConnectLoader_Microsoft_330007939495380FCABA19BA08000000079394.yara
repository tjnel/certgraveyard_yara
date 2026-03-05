import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330007939495380FCABA19BA08000000079394 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-15"
      version             = "1.0"

      hash                = "71f07a260efb92c9c2fa4b59cb02a3a76d4ffc1a24b05a0a64d615c860e52fd7"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: rmm.vendor-portal[.]net"

      signer              = "Julie Jorgensen"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:07:93:94:95:38:0f:ca:ba:19:ba:08:00:00:00:07:93:94"
      cert_thumbprint     = "7F47E499EBEE4B02024D1C6EDFB6D65C1D16019D"
      cert_valid_from     = "2026-02-15"
      cert_valid_to       = "2026-02-18"

      country             = "US"
      state               = "Maryland"
      locality            = "BALTIMORE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:07:93:94:95:38:0f:ca:ba:19:ba:08:00:00:00:07:93:94"
      )
}
