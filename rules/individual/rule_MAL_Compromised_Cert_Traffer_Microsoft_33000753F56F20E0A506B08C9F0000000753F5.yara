import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_33000753F56F20E0A506B08C9F0000000753F5 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-09"
      version             = "1.0"

      hash                = "fc1de9abdfe9a31a30aed6c10e6cb2e3226afc8fd50c66b139d0851676f71927"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:53:f5:6f:20:e0:a5:06:b0:8c:9f:00:00:00:07:53:f5"
      cert_thumbprint     = "F8EEC41B25A56F996E51595B56551251399EE1B0"
      cert_valid_from     = "2026-03-09"
      cert_valid_to       = "2026-03-12"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:53:f5:6f:20:e0:a5:06:b0:8c:9f:00:00:00:07:53:f5"
      )
}
