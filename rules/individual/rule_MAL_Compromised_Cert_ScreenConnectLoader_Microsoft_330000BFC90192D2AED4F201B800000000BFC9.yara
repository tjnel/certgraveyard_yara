import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000BFC90192D2AED4F201B800000000BFC9 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-04"
      version             = "1.0"

      hash                = "b0ead6f4f263982f1d89adbf64430f3cba82ed5a4302346ed725f1118e0e1cd5"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CHRISTIAN TORRES"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:bf:c9:01:92:d2:ae:d4:f2:01:b8:00:00:00:00:bf:c9"
      cert_thumbprint     = "EB43F571C3AC6ED24695BD0C6891DD8F0301DF4E"
      cert_valid_from     = "2026-05-04"
      cert_valid_to       = "2026-05-07"

      country             = "US"
      state               = "Texas"
      locality            = "UNIVERSAL CITY"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:bf:c9:01:92:d2:ae:d4:f2:01:b8:00:00:00:00:bf:c9"
      )
}
