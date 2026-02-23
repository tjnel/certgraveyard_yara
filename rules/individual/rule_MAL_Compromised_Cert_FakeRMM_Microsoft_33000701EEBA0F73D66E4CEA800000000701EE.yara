import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_33000701EEBA0F73D66E4CEA800000000701EE {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-20"
      version             = "1.0"

      hash                = "827a08808e1729b8f6711b522e0c572a7997b1c48ae2dc64fabc81ceab69183f"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers posing as a fake RMM tool. Ref: https://www.proofpoint.com/us/blog/threat-insight/dont-trustconnect-its-a-rat"

      signer              = "MELISSA LEHMAN"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:01:ee:ba:0f:73:d6:6e:4c:ea:80:00:00:00:07:01:ee"
      cert_thumbprint     = "310613FE171FB1DFA18AB713F65F9CAA71B4482C"
      cert_valid_from     = "2026-02-20"
      cert_valid_to       = "2026-02-23"

      country             = "US"
      state               = "Kansas"
      locality            = "clay center"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:01:ee:ba:0f:73:d6:6e:4c:ea:80:00:00:00:07:01:ee"
      )
}
