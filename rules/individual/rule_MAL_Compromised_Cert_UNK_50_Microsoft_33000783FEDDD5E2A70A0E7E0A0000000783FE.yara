import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000783FEDDD5E2A70A0E7E0A0000000783FE {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-06"
      version             = "1.0"

      hash                = "c634838f255e0a691f8be3eab45f2015f7f3572fba2124142cf9fe1d227416aa"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Brix Application Consulting Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:83:fe:dd:d5:e2:a7:0a:0e:7e:0a:00:00:00:07:83:fe"
      cert_thumbprint     = "03ca2fa1f8eed3f29f69b3fc95207f55c8d50af6"
      cert_valid_from     = "2026-02-06"
      cert_valid_to       = "2026-02-09"

      country             = "CA"
      state               = "Ontario"
      locality            = "Pickering"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:83:fe:dd:d5:e2:a7:0a:0e:7e:0a:00:00:00:07:83:fe"
      )
}
