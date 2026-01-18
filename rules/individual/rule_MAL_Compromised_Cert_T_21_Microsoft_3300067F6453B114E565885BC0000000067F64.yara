import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_3300067F6453B114E565885BC0000000067F64 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-17"
      version             = "1.0"

      hash                = "74c7afe099f09369957203ca7985e63f569438fcd3e6da7cfbee01f9b7d5c3e9"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:06:7f:64:53:b1:14:e5:65:88:5b:c0:00:00:00:06:7f:64"
      cert_thumbprint     = "FD8746502AA6A9F9938847F72ECD0B43EB5CE2BD"
      cert_valid_from     = "2026-01-17"
      cert_valid_to       = "2026-01-20"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:06:7f:64:53:b1:14:e5:65:88:5b:c0:00:00:00:06:7f:64"
      )
}
