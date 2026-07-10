import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330002AEDDB32C4491322056BA00000002AEDD {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-02"
      version             = "1.0"

      hash                = "e0dae1a04b7a3b2ae07377b0fd00681e9633532788870b3709a9e149f3ccf0e0"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "Xryus Technologies LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:02:ae:dd:b3:2c:44:91:32:20:56:ba:00:00:00:02:ae:dd"
      cert_thumbprint     = "317BD0AA0F75C228812464100B6B45EB495158F4"
      cert_valid_from     = "2026-07-02"
      cert_valid_to       = "2026-07-05"

      country             = "US"
      state               = "Delaware"
      locality            = "Lewes"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:02:ae:dd:b3:2c:44:91:32:20:56:ba:00:00:00:02:ae:dd"
      )
}
