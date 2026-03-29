import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300079EBC390DFE053B615058000000079EBC {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-24"
      version             = "1.0"

      hash                = "44b6aceca9302e75538237faf85946c7833c28e290de8941e50c72e6310e043a"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Juan Benavidez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:9e:bc:39:0d:fe:05:3b:61:50:58:00:00:00:07:9e:bc"
      cert_thumbprint     = "317B7913C3E410E4D7706AEEAC6CF339E0E2D2E9"
      cert_valid_from     = "2026-03-24"
      cert_valid_to       = "2026-03-27"

      country             = "US"
      state               = "Texas"
      locality            = "san antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:9e:bc:39:0d:fe:05:3b:61:50:58:00:00:00:07:9e:bc"
      )
}
