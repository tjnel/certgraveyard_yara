import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300074243FF56B1E8C3BF551C000000074243 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-05"
      version             = "1.0"

      hash                = "ca87d3d53290557dce61c193cdff308f3db400c011999470c371724cc171e9eb"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2 - dangeonbest[.]com"

      signer              = "Jerry Hayes"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:42:43:ff:56:b1:e8:c3:bf:55:1c:00:00:00:07:42:43"
      cert_thumbprint     = "559B8A3D3C07DC5F2378CD4C0441947F665FB294"
      cert_valid_from     = "2026-03-05"
      cert_valid_to       = "2026-03-08"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:42:43:ff:56:b1:e8:c3:bf:55:1c:00:00:00:07:42:43"
      )
}
