import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_3300073B04691AB4FE2AA4ACD7000000073B04 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-04"
      version             = "1.0"

      hash                = "d7fb1b329cf15e9bb814a696788a65d3fff26289bb56e3c015b007027e47f152"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = "Malware campaign targeting BR users via fake documents. C2: jmkkload[.]com/bba13d314ed6c2ec94/"

      signer              = "Julie Jorgensen"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:3b:04:69:1a:b4:fe:2a:a4:ac:d7:00:00:00:07:3b:04"
      cert_thumbprint     = "b010ff1b691422bc0ab3f992a8a52a9c128f39c6"
      cert_valid_from     = "2026-03-04"
      cert_valid_to       = "2026-03-07"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:3b:04:69:1a:b4:fe:2a:a4:ac:d7:00:00:00:07:3b:04"
      )
}
