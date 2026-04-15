import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_330007D4E2A923E5F22C2A519000000007D4E2 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-03"
      version             = "1.0"

      hash                = "8d2f71d02a8cf5fabb29f2e25b02bf1916c6547d9934d01eb1580b746fdaecfc"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DAWN RENEE"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:d4:e2:a9:23:e5:f2:2c:2a:51:90:00:00:00:07:d4:e2"
      cert_thumbprint     = "515B09E624941A703A9F6B5948CA8F99EC753B2A"
      cert_valid_from     = "2026-04-03"
      cert_valid_to       = "2026-04-06"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:d4:e2:a9:23:e5:f2:2c:2a:51:90:00:00:00:07:d4:e2"
      )
}
