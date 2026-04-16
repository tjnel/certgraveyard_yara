import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_330007E88C865C39C4C86DF29800000007E88C {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-06"
      version             = "1.0"

      hash                = "f0fd766df65ac4e2a2b2dc6417513dfd20fb97db5ad8f6957f94e76ef49a0dbf"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DAWN RENEE"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:e8:8c:86:5c:39:c4:c8:6d:f2:98:00:00:00:07:e8:8c"
      cert_thumbprint     = "BC777692929555DD48A04F0B7E8AD0E30930C14F"
      cert_valid_from     = "2026-04-06"
      cert_valid_to       = "2026-04-09"

      country             = "US"
      state               = "Hawaii"
      locality            = "KULA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:e8:8c:86:5c:39:c4:c8:6d:f2:98:00:00:00:07:e8:8c"
      )
}
