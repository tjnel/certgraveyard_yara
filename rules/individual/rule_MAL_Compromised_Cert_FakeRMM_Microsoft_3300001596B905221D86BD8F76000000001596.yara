import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_3300001596B905221D86BD8F76000000001596 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-14"
      version             = "1.0"

      hash                = "76f7ed2906cc0d6fdccecefda3a1e004dd2d9bcf47e908c786c67c27ea00e100"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:15:96:b9:05:22:1d:86:bd:8f:76:00:00:00:00:15:96"
      cert_thumbprint     = "FEE62C0AF6E19ED38600BAD4343333321F2B857C"
      cert_valid_from     = "2026-04-14"
      cert_valid_to       = "2026-04-17"

      country             = "US"
      state               = "Tennessee"
      locality            = "nashville"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:15:96:b9:05:22:1d:86:bd:8f:76:00:00:00:00:15:96"
      )
}
