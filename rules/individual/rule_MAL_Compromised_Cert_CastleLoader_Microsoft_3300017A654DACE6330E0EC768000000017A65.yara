import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300017A654DACE6330E0EC768000000017A65 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-27"
      version             = "1.0"

      hash                = "d90d4acca9b6bd3be23f87587cf48396ad831c51280ea65e76a6f00ef3a1472f"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Elusive Techno"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:7a:65:4d:ac:e6:33:0e:0e:c7:68:00:00:00:01:7a:65"
      cert_thumbprint     = "EA98A6C6EEC6A9694C76473FFD5397129F86432C"
      cert_valid_from     = "2026-05-27"
      cert_valid_to       = "2026-05-30"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:7a:65:4d:ac:e6:33:0e:0e:c7:68:00:00:00:01:7a:65"
      )
}
