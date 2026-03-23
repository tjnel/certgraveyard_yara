import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300077E668F71119BE1AEC322000000077E66 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-20"
      version             = "1.0"

      hash                = "730a9f417868ce3fc3c7d8b039d0373092dac277e477104bb23547eca29e6373"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JORGE LOPEZ"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:7e:66:8f:71:11:9b:e1:ae:c3:22:00:00:00:07:7e:66"
      cert_thumbprint     = "C5CD0E409A463026189AB4F4B9C0F4BB51416005"
      cert_valid_from     = "2026-03-20"
      cert_valid_to       = "2026-03-23"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:7e:66:8f:71:11:9b:e1:ae:c3:22:00:00:00:07:7e:66"
      )
}
