import "pe"

rule MAL_Compromised_Cert_FakeNDASign_Microsoft_330007BAE25F25ABAAD971133B00000007BAE2 {
   meta:
      description         = "Detects FakeNDASign with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-30"
      version             = "1.0"

      hash                = "e25fa1d0a29eaea8b9a60a2d39c73f147efd544d391a4a4e115df13534226481"
      malware             = "FakeNDASign"
      malware_type        = "Unknown"
      malware_notes       = "Malware campaign targeting job-seekers with fake landing ndavia[.]com"

      signer              = "Robert Walters"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:ba:e2:5f:25:ab:aa:d9:71:13:3b:00:00:00:07:ba:e2"
      cert_thumbprint     = "583010C39855AE4F2E246D06D1D9D3B74653EAC0"
      cert_valid_from     = "2026-03-30"
      cert_valid_to       = "2026-04-02"

      country             = "US"
      state               = "California"
      locality            = "Placentia"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:ba:e2:5f:25:ab:aa:d9:71:13:3b:00:00:00:07:ba:e2"
      )
}
