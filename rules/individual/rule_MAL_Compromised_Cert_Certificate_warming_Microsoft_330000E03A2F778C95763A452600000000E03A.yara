import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Microsoft_330000E03A2F778C95763A452600000000E03A {
   meta:
      description         = "Detects Certificate warming with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-10"
      version             = "1.0"

      hash                = "9220a494d3d719a46de8c93994ed386e88457df3db7d87ab89644453eab0cf24"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = "This certificate is being prepared for a campaign by using it for benign installs."

      signer              = "TERESA ANN BOSWELL"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:e0:3a:2f:77:8c:95:76:3a:45:26:00:00:00:00:e0:3a"
      cert_thumbprint     = "87F04635728905F88BB1F6A44CAADE1289037B1A"
      cert_valid_from     = "2026-05-10"
      cert_valid_to       = "2026-05-13"

      country             = "US"
      state               = "Arizona"
      locality            = "Mesa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:e0:3a:2f:77:8c:95:76:3a:45:26:00:00:00:00:e0:3a"
      )
}
