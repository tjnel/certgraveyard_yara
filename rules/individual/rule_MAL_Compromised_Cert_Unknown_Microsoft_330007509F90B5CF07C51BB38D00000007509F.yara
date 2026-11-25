import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330007509F90B5CF07C51BB38D00000007509F {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-30"
      version             = "1.0"

      hash                = "98e3bbaced5719581f12aaf603eb9c08519b8a988c202cf085b2c6cd4a36276f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Technoservice B.V."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:07:50:9f:90:b5:cf:07:c5:1b:b3:8d:00:00:00:07:50:9f"
      cert_thumbprint     = "aae1117591a68bb3ab0689c5509f58048145f364"
      cert_valid_from     = "2026-09-30"
      cert_valid_to       = "2026-10-03"

      country             = "NL"
      state               = "Zuid-Holland"
      locality            = "Hellevoetsluis"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:07:50:9f:90:b5:cf:07:c5:1b:b3:8d:00:00:00:07:50:9f"
      )
}
