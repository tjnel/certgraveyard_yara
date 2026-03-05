import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_6B44BA90EFCD9804F553E6E5 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-19"
      version             = "1.0"

      hash                = "449be9e617efdbbf57169e452ec4d20935e67e524bc26335a73209821873f3c7"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OR KAHOL LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6b:44:ba:90:ef:cd:98:04:f5:53:e6:e5"
      cert_thumbprint     = "4217BAC417F82CC3416ACD4E3954DD17A1E8E23D"
      cert_valid_from     = "2024-03-19"
      cert_valid_to       = "2025-03-20"

      country             = "IL"
      state               = "Central District"
      locality            = "Ra'anana"
      email               = "info@orkahol.com"
      rdn_serial_number   = "516891165"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6b:44:ba:90:ef:cd:98:04:f5:53:e6:e5"
      )
}
