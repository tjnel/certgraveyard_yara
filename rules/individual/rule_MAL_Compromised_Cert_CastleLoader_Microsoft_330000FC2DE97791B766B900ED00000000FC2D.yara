import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330000FC2DE97791B766B900ED00000000FC2D {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-11"
      version             = "1.0"

      hash                = "909099a2fbafbac8da494b8e40f2dbbf9e50699d62a7ff660612572736f14f67"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TECHNOLOGY APPRAISALS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:fc:2d:e9:77:91:b7:66:b9:00:ed:00:00:00:00:fc:2d"
      cert_thumbprint     = "6C51C998F5E952C8A7AC6C046CBB70352845A51A"
      cert_valid_from     = "2026-05-11"
      cert_valid_to       = "2026-05-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:fc:2d:e9:77:91:b7:66:b9:00:ed:00:00:00:00:fc:2d"
      )
}
