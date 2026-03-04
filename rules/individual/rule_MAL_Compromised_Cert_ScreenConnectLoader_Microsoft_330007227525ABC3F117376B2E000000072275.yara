import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330007227525ABC3F117376B2E000000072275 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-28"
      version             = "1.0"

      hash                = "aeee527e9ea6a87040019f31abeaf54d3bcda214b2fe040f3334ccf8644eb953"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JAMIE QUIGGINS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:22:75:25:ab:c3:f1:17:37:6b:2e:00:00:00:07:22:75"
      cert_thumbprint     = "8E6495E919929347634FB6D0E8FB4F0DDFF0D12E"
      cert_valid_from     = "2026-02-28"
      cert_valid_to       = "2026-03-03"

      country             = "US"
      state               = "California"
      locality            = "Los Angeles"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:22:75:25:ab:c3:f1:17:37:6b:2e:00:00:00:07:22:75"
      )
}
