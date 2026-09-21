import "pe"

rule MAL_Compromised_Cert_SideWinder_Microsoft_3300063FA6F31FEAB00FE68F9E000000063FA6 {
   meta:
      description         = "Detects SideWinder with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-10"
      version             = "1.0"

      hash                = "54d95a19a2ce05b1d8c66c21f2863658960f609fa809cdce43b6a0192a8eda6e"
      malware             = "SideWinder"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alysen Mendez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:06:3f:a6:f3:1f:ea:b0:0f:e6:8f:9e:00:00:00:06:3f:a6"
      cert_thumbprint     = "65aefb8b2b04c84db1cb9e7255cd88e8c1794b67"
      cert_valid_from     = "2026-09-10"
      cert_valid_to       = "2026-09-13"

      country             = "US"
      state               = "New Jersey"
      locality            = "LITTLE FERRY"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:06:3f:a6:f3:1f:ea:b0:0f:e6:8f:9e:00:00:00:06:3f:a6"
      )
}
