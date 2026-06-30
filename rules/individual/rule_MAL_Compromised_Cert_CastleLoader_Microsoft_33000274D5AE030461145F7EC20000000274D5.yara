import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_33000274D5AE030461145F7EC20000000274D5 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-25"
      version             = "1.0"

      hash                = "186516a0dafa253b0182aa745e48cb23623a907cae922b7d1f802795ada7b888"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: qorvethix.com"

      signer              = "SOCIEDADE AGRO-PECUÃRIA OVIMOR, UNIPESSOAL, LDA"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:02:74:d5:ae:03:04:61:14:5f:7e:c2:00:00:00:02:74:d5"
      cert_thumbprint     = "9D1802E7B0F40E2F1C5597C87B9974F6D72E311B"
      cert_valid_from     = "2026-06-25"
      cert_valid_to       = "2026-06-28"

      country             = "PT"
      state               = "Évora"
      locality            = "SILVEIRAS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:02:74:d5:ae:03:04:61:14:5f:7e:c2:00:00:00:02:74:d5"
      )
}
