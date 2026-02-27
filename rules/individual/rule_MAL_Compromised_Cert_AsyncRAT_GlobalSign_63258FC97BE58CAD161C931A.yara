import "pe"

rule MAL_Compromised_Cert_AsyncRAT_GlobalSign_63258FC97BE58CAD161C931A {
   meta:
      description         = "Detects AsyncRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-08"
      version             = "1.0"

      hash                = "42d8f7e1ebb5ab2e948db328d28361df0e1ce8f8ce0c91b6a65f9a771a9da56c"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NIGHTRAPTOR SİBER GÜVENLİK TEKNOLOJİ YAZILIM DAN.LTD.ŞTİ."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 CodeSigning CA 2020"
      cert_serial         = "63:25:8f:c9:7b:e5:8c:ad:16:1c:93:1a"
      cert_thumbprint     = "1AB5E4E078A454CD24BBB57208F54DD2ED576929"
      cert_valid_from     = "2025-04-08"
      cert_valid_to       = "2026-04-09"

      country             = "TR"
      state               = "İSTANBUL"
      locality            = "SANCAKTEPE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 CodeSigning CA 2020" and
         sig.serial == "63:25:8f:c9:7b:e5:8c:ad:16:1c:93:1a"
      )
}
