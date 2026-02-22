import "pe"

rule MAL_Compromised_Cert_AxolotlLoader_Microsoft_330007DC4E73FC0B983770783900000007DC4E {
   meta:
      description         = "Detects AxolotlLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-19"
      version             = "1.0"

      hash                = "8b6e79b74859b22dbe9ef9d9ae2c27236640f062560fb4a9d743245d2389091a"
      malware             = "AxolotlLoader"
      malware_type        = "Loader"
      malware_notes       = "Fake Task manager. This signer is used to sign several tools that aren't normally signed. The software reaches out to a domain: bloganimals.com"

      signer              = "BUSINESS CONSULTING SP Z O O"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:dc:4e:73:fc:0b:98:37:70:78:39:00:00:00:07:dc:4e"
      cert_thumbprint     = "AD95998E92FE764EE68F4DC35109B2A7328DA1F1"
      cert_valid_from     = "2026-02-19"
      cert_valid_to       = "2026-02-22"

      country             = "PL"
      state               = "Małopolskie"
      locality            = "Swiatniki Gorne"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:dc:4e:73:fc:0b:98:37:70:78:39:00:00:00:07:dc:4e"
      )
}
