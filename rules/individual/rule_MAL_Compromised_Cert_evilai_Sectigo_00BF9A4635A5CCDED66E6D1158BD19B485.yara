import "pe"

rule MAL_Compromised_Cert_evilai_Sectigo_00BF9A4635A5CCDED66E6D1158BD19B485 {
   meta:
      description         = "Detects evilai with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-23"
      version             = "1.0"

      hash                = "af4400a89955192d31f6590718792283a0911f9ee1ba06fdc6dd12edfedbac15"
      malware             = "evilai"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Astras Novei LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:bf:9a:46:35:a5:cc:de:d6:6e:6d:11:58:bd:19:b4:85"
      cert_thumbprint     = "FABCB144F3E07935A609DC5808BBA45B127ED634"
      cert_valid_from     = "2025-12-23"
      cert_valid_to       = "2026-12-23"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:bf:9a:46:35:a5:cc:de:d6:6e:6d:11:58:bd:19:b4:85"
      )
}
