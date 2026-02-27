import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_3300071A845B6BA727FE6BDEF2000000071A84 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-24"
      version             = "1.0"

      hash                = "ca1730909d5f4d75dca58e0e7ba0340cbf2a16bbb60f8a76fd37a45d8e216f8b"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers posing as a fake RMM tool. Ref: https://www.proofpoint.com/us/blog/threat-insight/dont-trustconnect-its-a-rat"

      signer              = "NICHOLAS HALL"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:1a:84:5b:6b:a7:27:fe:6b:de:f2:00:00:00:07:1a:84"
      cert_thumbprint     = "ECDA81777858651510C5C6CB2750AEF8FF0486D1"
      cert_valid_from     = "2026-02-24"
      cert_valid_to       = "2026-02-27"

      country             = "US"
      state               = "Indiana"
      locality            = "HANOVER"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:1a:84:5b:6b:a7:27:fe:6b:de:f2:00:00:00:07:1a:84"
      )
}
