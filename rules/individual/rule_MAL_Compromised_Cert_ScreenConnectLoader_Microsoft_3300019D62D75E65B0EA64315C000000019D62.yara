import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300019D62D75E65B0EA64315C000000019D62 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-02"
      version             = "1.0"

      hash                = "d96aa8d796b4137d876de9821f2a04a1718ddd55c648a5e0b7ad6d18ff090016"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Danielle Hale"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:9d:62:d7:5e:65:b0:ea:64:31:5c:00:00:00:01:9d:62"
      cert_thumbprint     = "744A6C315C425618CDF93EFC308B9BC06986621E"
      cert_valid_from     = "2026-06-02"
      cert_valid_to       = "2026-06-05"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:9d:62:d7:5e:65:b0:ea:64:31:5c:00:00:00:01:9d:62"
      )
}
