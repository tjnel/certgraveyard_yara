import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_3300079EBC390DFE053B615058000000079EBC {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-24"
      version             = "1.0"

      hash                = "6f7c9cdf8cee3978f8aa0e218a640a93ed2fce44c58f7107790dbee994f617a4"
      malware             = "FakeRMM"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "Juan Benavidez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:9e:bc:39:0d:fe:05:3b:61:50:58:00:00:00:07:9e:bc"
      cert_thumbprint     = "317B7913C3E410E4D7706AEEAC6CF339E0E2D2E9"
      cert_valid_from     = "2026-03-24"
      cert_valid_to       = "2026-03-27"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:9e:bc:39:0d:fe:05:3b:61:50:58:00:00:00:07:9e:bc"
      )
}
