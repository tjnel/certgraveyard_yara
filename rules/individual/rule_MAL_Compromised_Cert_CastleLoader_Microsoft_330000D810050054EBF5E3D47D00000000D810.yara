import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330000D810050054EBF5E3D47D00000000D810 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-09"
      version             = "1.0"

      hash                = "92c89c3e7dd6b78355c507bfe684998b743566c890b4a126e89a9b3eee2626f2"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: elvaronexkas[.]com"

      signer              = "Slims Software"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:d8:10:05:00:54:eb:f5:e3:d4:7d:00:00:00:00:d8:10"
      cert_thumbprint     = "9EEE7B105CAF89170FFC47F2B4DEE2CC192CF858"
      cert_valid_from     = "2026-05-09"
      cert_valid_to       = "2026-05-12"

      country             = "NL"
      state               = "Utrecht"
      locality            = "Utrecht"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:d8:10:05:00:54:eb:f5:e3:d4:7d:00:00:00:00:d8:10"
      )
}
