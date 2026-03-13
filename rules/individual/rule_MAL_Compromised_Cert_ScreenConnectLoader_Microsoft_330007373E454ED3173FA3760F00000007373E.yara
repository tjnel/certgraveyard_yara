import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330007373E454ED3173FA3760F00000007373E {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-03"
      version             = "1.0"

      hash                = "dfd0bf6331e7c57ae85798c0b48c35e19bd699163ffbc0dbeafc9607ed413063"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "JAMIE QUIGGINS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:37:3e:45:4e:d3:17:3f:a3:76:0f:00:00:00:07:37:3e"
      cert_thumbprint     = "7A79D6CD648866C7EAD8E8EEE88BBCEE47FA5B0F"
      cert_valid_from     = "2026-03-03"
      cert_valid_to       = "2026-03-06"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:37:3e:45:4e:d3:17:3f:a3:76:0f:00:00:00:07:37:3e"
      )
}
