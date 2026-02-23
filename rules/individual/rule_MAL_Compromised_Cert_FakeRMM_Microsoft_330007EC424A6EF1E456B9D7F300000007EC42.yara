import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_330007EC424A6EF1E456B9D7F300000007EC42 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-21"
      version             = "1.0"

      hash                = "28cc12c092e331809e92dd20604ee1f646cbb96f8426f3944214605f590fe7df"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers posing as a RMM tool. Ref: https://www.proofpoint.com/us/blog/threat-insight/dont-trustconnect-its-a-rat"

      signer              = "NICHOLAS HALL"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:ec:42:4a:6e:f1:e4:56:b9:d7:f3:00:00:00:07:ec:42"
      cert_thumbprint     = "8E3A7719FC7004C5987272E1CA236F4B6F99A14D"
      cert_valid_from     = "2026-02-21"
      cert_valid_to       = "2026-02-24"

      country             = "US"
      state               = "Indiana"
      locality            = "HANOVER"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:ec:42:4a:6e:f1:e4:56:b9:d7:f3:00:00:00:07:ec:42"
      )
}
