import "pe"

rule MAL_Compromised_Cert_SideWinder_Microsoft_330007994E3AC7660B30A2086000000007994E {
   meta:
      description         = "Detects SideWinder with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-04"
      version             = "1.0"

      hash                = "2fe66bca36b205525244d27fd040f2c894ecaafcf84d25d0865451b5d25266c8"
      malware             = "SideWinder"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ashley Marie Boynton"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:07:99:4e:3a:c7:66:0b:30:a2:08:60:00:00:00:07:99:4e"
      cert_thumbprint     = "07e677a110c9fe6f180933bb1354af9046740b49"
      cert_valid_from     = "2026-10-04"
      cert_valid_to       = "2026-10-07"

      country             = "US"
      state               = "nv"
      locality            = "SPARKS"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:07:99:4e:3a:c7:66:0b:30:a2:08:60:00:00:00:07:99:4e"
      )
}
