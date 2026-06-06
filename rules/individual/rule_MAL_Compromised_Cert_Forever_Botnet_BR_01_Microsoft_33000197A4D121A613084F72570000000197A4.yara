import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_33000197A4D121A613084F72570000000197A4 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-01"
      version             = "1.0"

      hash                = "1768cd3d250cdf365e7242707fe8864eb054f9446789f9928324c3133773ca57"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:97:a4:d1:21:a6:13:08:4f:72:57:00:00:00:01:97:a4"
      cert_thumbprint     = "6CACD059D76FADE6EB982B50779B34BB7BDE50BB"
      cert_valid_from     = "2026-06-01"
      cert_valid_to       = "2026-06-04"

      country             = "DK"
      state               = "Central Jutland"
      locality            = "Hammel"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:97:a4:d1:21:a6:13:08:4f:72:57:00:00:00:01:97:a4"
      )
}
