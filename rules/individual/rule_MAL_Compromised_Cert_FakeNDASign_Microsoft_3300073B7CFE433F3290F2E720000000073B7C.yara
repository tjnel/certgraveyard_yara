import "pe"

rule MAL_Compromised_Cert_FakeNDASign_Microsoft_3300073B7CFE433F3290F2E720000000073B7C {
   meta:
      description         = "Detects FakeNDASign with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-04"
      version             = "1.0"

      hash                = "e807be75045514f477ef6ccaf07f211101a3df7c14971550bb80a14aa20ab00f"
      malware             = "FakeNDASign"
      malware_type        = "Unknown"
      malware_notes       = "Malware campaign targeting job-seekers with fake landing ndavia[.]com"

      signer              = "Brice Carpenter"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:3b:7c:fe:43:3f:32:90:f2:e7:20:00:00:00:07:3b:7c"
      cert_thumbprint     = "F0C7D54C443A93CE3F4EA910294B43A440F06921"
      cert_valid_from     = "2026-03-04"
      cert_valid_to       = "2026-03-07"

      country             = "US"
      state               = "Wyoming"
      locality            = "CASPER"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:3b:7c:fe:43:3f:32:90:f2:e7:20:00:00:00:07:3b:7c"
      )
}
