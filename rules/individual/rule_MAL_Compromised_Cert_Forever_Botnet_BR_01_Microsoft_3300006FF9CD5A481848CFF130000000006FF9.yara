import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_3300006FF9CD5A481848CFF130000000006FF9 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-23"
      version             = "1.0"

      hash                = "9d3f0f826f3c154499bba1c241ea658ce3d3639489cb19b79eb4534e9402f6f0"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "CHRISTIAN SAEZ LORENZO"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:6f:f9:cd:5a:48:18:48:cf:f1:30:00:00:00:00:6f:f9"
      cert_thumbprint     = "77378FE69134AAFD4E2451B9CBF570F14FE84483"
      cert_valid_from     = "2026-04-23"
      cert_valid_to       = "2026-04-26"

      country             = "US"
      state               = "Alaska"
      locality            = "KETCHIKAN"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:6f:f9:cd:5a:48:18:48:cf:f1:30:00:00:00:00:6f:f9"
      )
}
