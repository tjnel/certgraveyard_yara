import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_330007E678B2E9E6A09C386D6E00000007E678 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-20"
      version             = "1.0"

      hash                = "63450bf8e4abe98ba2b27b17d8da918848b466c0e38249ed4a71dc663f102172"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers posing as a fake RMM tool. Ref: https://www.proofpoint.com/us/blog/threat-insight/dont-trustconnect-its-a-rat"

      signer              = "Khyree Woodberry"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:e6:78:b2:e9:e6:a0:9c:38:6d:6e:00:00:00:07:e6:78"
      cert_thumbprint     = "C2DF7637E5014BB5554BE762DE6C6F0A63DC83CD"
      cert_valid_from     = "2026-02-20"
      cert_valid_to       = "2026-02-23"

      country             = "US"
      state               = "Maryland"
      locality            = "baltimore"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:e6:78:b2:e9:e6:a0:9c:38:6d:6e:00:00:00:07:e6:78"
      )
}
