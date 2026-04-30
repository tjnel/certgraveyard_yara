import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_3300059886F858BD0AB8E36907000000059886 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-05"
      version             = "1.0"

      hash                = "7ee03083416ea73e004b75a389fb5c1f55e7bc00d305222b0756f1a8ea1135ab"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:98:86:f8:58:bd:0a:b8:e3:69:07:00:00:00:05:98:86"
      cert_thumbprint     = "9234E5373B70B1C396637D71864AB5D09147B6DC"
      cert_valid_from     = "2025-12-05"
      cert_valid_to       = "2025-12-08"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:98:86:f8:58:bd:0a:b8:e3:69:07:00:00:00:05:98:86"
      )
}
