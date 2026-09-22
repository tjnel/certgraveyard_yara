import "pe"

rule MAL_Compromised_Cert_SideWinder_Microsoft_330006A547D3085EB78AEAC52200000006A547 {
   meta:
      description         = "Detects SideWinder with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-17"
      version             = "1.0"

      hash                = "763ac38c6373a4d5bd820b904e934c459e57bee6016b5325368a45f7f5b8753e"
      malware             = "SideWinder"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Brittany Ann Martin"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:06:a5:47:d3:08:5e:b7:8a:ea:c5:22:00:00:00:06:a5:47"
      cert_thumbprint     = "9326ffc3b61a1186f1611712ef27efd5aa65144f"
      cert_valid_from     = "2026-09-17"
      cert_valid_to       = "2026-09-20"

      country             = "US"
      state               = "fl"
      locality            = "riverview"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:06:a5:47:d3:08:5e:b7:8a:ea:c5:22:00:00:00:06:a5:47"
      )
}
