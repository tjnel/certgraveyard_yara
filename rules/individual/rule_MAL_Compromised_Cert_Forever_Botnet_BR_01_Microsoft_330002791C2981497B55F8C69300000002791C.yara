import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330002791C2981497B55F8C69300000002791C {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-25"
      version             = "1.0"

      hash                = "ebaf5aded88ec40f16f1448586633ff44d907abb2d8990cb52ba7f6a6e405831"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOCIEDADE AGRO-PECUÃRIA OVIMOR, UNIPESSOAL, LDA"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:02:79:1c:29:81:49:7b:55:f8:c6:93:00:00:00:02:79:1c"
      cert_thumbprint     = "1BA5A5A23AD18A60DB7B9E4B2782DFE1265EBF09"
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
         sig.serial == "33:00:02:79:1c:29:81:49:7b:55:f8:c6:93:00:00:00:02:79:1c"
      )
}
