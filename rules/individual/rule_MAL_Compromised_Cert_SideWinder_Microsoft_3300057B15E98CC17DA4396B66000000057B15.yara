import "pe"

rule MAL_Compromised_Cert_SideWinder_Microsoft_3300057B15E98CC17DA4396B66000000057B15 {
   meta:
      description         = "Detects SideWinder with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-04"
      version             = "1.0"

      hash                = "4e73e140243fbaa9d1213e6f0acd6f9029c0891fac92cdee3d9a1a70891f3dc8"
      malware             = "SideWinder"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alysen Mendez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:05:7b:15:e9:8c:c1:7d:a4:39:6b:66:00:00:00:05:7b:15"
      cert_thumbprint     = "9169cce13558d3d7ae13bd873d048ace7316e880"
      cert_valid_from     = "2026-09-04"
      cert_valid_to       = "2026-09-07"

      country             = "US"
      state               = "New Jersey"
      locality            = "LITTLE FERRY"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:05:7b:15:e9:8c:c1:7d:a4:39:6b:66:00:00:00:05:7b:15"
      )
}
