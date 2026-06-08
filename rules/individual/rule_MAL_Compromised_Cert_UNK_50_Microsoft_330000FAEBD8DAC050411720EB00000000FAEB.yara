import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330000FAEBD8DAC050411720EB00000000FAEB {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-11"
      version             = "1.0"

      hash                = "da2e9d6e9d74babdf51291a9728dfdd988b990c0e675def2c96d859fd5430e32"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "A&A Interactive Media Group"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:fa:eb:d8:da:c0:50:41:17:20:eb:00:00:00:00:fa:eb"
      cert_thumbprint     = "C51A89F2EEF4132E75A107A3953037901DF95651"
      cert_valid_from     = "2026-05-11"
      cert_valid_to       = "2026-05-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:fa:eb:d8:da:c0:50:41:17:20:eb:00:00:00:00:fa:eb"
      )
}
