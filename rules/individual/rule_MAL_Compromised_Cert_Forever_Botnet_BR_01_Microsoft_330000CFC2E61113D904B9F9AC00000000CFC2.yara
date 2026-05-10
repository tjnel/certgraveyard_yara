import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330000CFC2E61113D904B9F9AC00000000CFC2 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-08"
      version             = "1.0"

      hash                = "25d18a2bf31ff3ce40f2d042cbba8dc5a6cd4f680adcacc763c62d2e64168729"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:cf:c2:e6:11:13:d9:04:b9:f9:ac:00:00:00:00:cf:c2"
      cert_thumbprint     = "599E7ABA5E0586E43EB7D0E3777BC9B8E1AB7E3D"
      cert_valid_from     = "2026-05-08"
      cert_valid_to       = "2026-05-11"

      country             = "DK"
      state               = "Central Jutland"
      locality            = "Hammel"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:cf:c2:e6:11:13:d9:04:b9:f9:ac:00:00:00:00:cf:c2"
      )
}
