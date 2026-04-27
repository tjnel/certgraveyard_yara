import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_33000879E850AD2CA7CCC013F00000000879E8 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-16"
      version             = "1.0"

      hash                = "2336ef2777274c5ebffa98e86a6085d8de354267fe85f9ee9ea74fd92c051724"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mariah Lingle"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:79:e8:50:ad:2c:a7:cc:c0:13:f0:00:00:00:08:79:e8"
      cert_thumbprint     = "8A302AB8685AC70C4AEB4E3B2E369727E78D544B"
      cert_valid_from     = "2026-03-16"
      cert_valid_to       = "2026-03-19"

      country             = "US"
      state               = "Montana"
      locality            = "Columbia Fals"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:79:e8:50:ad:2c:a7:cc:c0:13:f0:00:00:00:08:79:e8"
      )
}
