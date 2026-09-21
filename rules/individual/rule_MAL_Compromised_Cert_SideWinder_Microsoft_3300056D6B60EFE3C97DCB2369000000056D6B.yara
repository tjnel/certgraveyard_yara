import "pe"

rule MAL_Compromised_Cert_SideWinder_Microsoft_3300056D6B60EFE3C97DCB2369000000056D6B {
   meta:
      description         = "Detects SideWinder with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-03"
      version             = "1.0"

      hash                = "9c692a0bf6d9d784e705dbd5f8fe8089d31eeab6fe196f9288573fd4aa3c5fa6"
      malware             = "SideWinder"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alysen Mendez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:05:6d:6b:60:ef:e3:c9:7d:cb:23:69:00:00:00:05:6d:6b"
      cert_thumbprint     = "ff3fc87d2d327b6cfeae83ae3da1a9e50caf6bd4"
      cert_valid_from     = "2026-09-03"
      cert_valid_to       = "2026-09-06"

      country             = "US"
      state               = "New Jersey"
      locality            = "LITTLE FERRY"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:05:6d:6b:60:ef:e3:c9:7d:cb:23:69:00:00:00:05:6d:6b"
      )
}
