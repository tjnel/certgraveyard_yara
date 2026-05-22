import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000BC1CB8A93346B0E6763700000000BC1C {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-04"
      version             = "1.0"

      hash                = "85ddec4a2c2d0d894356b98a4985241720e366eb53241a9df90724d4232dbc20"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Avery Benavidez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:bc:1c:b8:a9:33:46:b0:e6:76:37:00:00:00:00:bc:1c"
      cert_thumbprint     = "94E2041E572611F7475398735391F2840811E981"
      cert_valid_from     = "2026-05-04"
      cert_valid_to       = "2026-05-07"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:bc:1c:b8:a9:33:46:b0:e6:76:37:00:00:00:00:bc:1c"
      )
}
