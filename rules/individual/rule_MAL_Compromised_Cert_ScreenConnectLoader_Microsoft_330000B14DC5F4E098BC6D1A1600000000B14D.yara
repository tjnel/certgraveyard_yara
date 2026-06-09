import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000B14DC5F4E098BC6D1A1600000000B14D {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-02"
      version             = "1.0"

      hash                = "9663a7714d97bdf640c602fe8b640498ab1c428f60fcc5dd508f4b44cfc35bb3"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ana Lazcon"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:b1:4d:c5:f4:e0:98:bc:6d:1a:16:00:00:00:00:b1:4d"
      cert_thumbprint     = "5EFA685FE4DAB7EF9E95C5D139CCDFB7D4362DFC"
      cert_valid_from     = "2026-05-02"
      cert_valid_to       = "2026-05-05"

      country             = "US"
      state               = "Texas"
      locality            = "san antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:b1:4d:c5:f4:e0:98:bc:6d:1a:16:00:00:00:00:b1:4d"
      )
}
