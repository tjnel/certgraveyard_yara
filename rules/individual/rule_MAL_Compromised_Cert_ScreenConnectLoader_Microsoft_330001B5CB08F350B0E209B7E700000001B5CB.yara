import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001B5CB08F350B0E209B7E700000001B5CB {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-05"
      version             = "1.0"

      hash                = "24bc3936ae9054ab66ace68d6b23ca3e8853ebb7239c32651d36c93459d51793"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:b5:cb:08:f3:50:b0:e2:09:b7:e7:00:00:00:01:b5:cb"
      cert_thumbprint     = "DE76D2C1906CDA8CE8CE27800A9B2DEC35D68361"
      cert_valid_from     = "2026-06-05"
      cert_valid_to       = "2026-06-08"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:b5:cb:08:f3:50:b0:e2:09:b7:e7:00:00:00:01:b5:cb"
      )
}
