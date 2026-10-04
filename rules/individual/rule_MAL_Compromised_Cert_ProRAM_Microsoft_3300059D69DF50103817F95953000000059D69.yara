import "pe"

rule MAL_Compromised_Cert_ProRAM_Microsoft_3300059D69DF50103817F95953000000059D69 {
   meta:
      description         = "Detects ProRAM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-06"
      version             = "1.0"

      hash                = "c3394372c2000643ce385269b0d8c648ccb8c833076a84bde397a3c01e7b4a5b"
      malware             = "ProRAM"
      malware_type        = "Unknown"
      malware_notes       = "Ref: https://kabir.au/blog/uncovering-a-live-watering-hole-attack"

      signer              = "Wijtvliet Agro"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:05:9d:69:df:50:10:38:17:f9:59:53:00:00:00:05:9d:69"
      cert_thumbprint     = "04974e6261ed47453cb34a7ea9c313741fd608ca"
      cert_valid_from     = "2026-09-06"
      cert_valid_to       = "2026-09-09"

      country             = "NL"
      state               = "Noord-Brabant"
      locality            = "Moerdijk"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:05:9d:69:df:50:10:38:17:f9:59:53:00:00:00:05:9d:69"
      )
}
