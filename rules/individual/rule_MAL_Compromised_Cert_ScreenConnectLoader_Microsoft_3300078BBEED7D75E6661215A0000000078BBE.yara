import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300078BBEED7D75E6661215A0000000078BBE {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-22"
      version             = "1.0"

      hash                = "2c0495c4fc64fee3d8a8411b5cc5d1298348b204dcd5c597ea356a1afc9b01d3"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Johnson Tredaytrin Keyshawn"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:8b:be:ed:7d:75:e6:66:12:15:a0:00:00:00:07:8b:be"
      cert_thumbprint     = "9363B0F586C5E86A219AD640F30D660F2E6FD3FB"
      cert_valid_from     = "2026-03-22"
      cert_valid_to       = "2026-03-25"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:8b:be:ed:7d:75:e6:66:12:15:a0:00:00:00:07:8b:be"
      )
}
