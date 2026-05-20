import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300011EA5F3D157F1A06BD1D2000000011EA5 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-17"
      version             = "1.0"

      hash                = "fb7e4bd1dcd2ddbace63f7cb27c0c1d64f72acc30e7b73596d74ab86a3e09121"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chaunesey Morrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:1e:a5:f3:d1:57:f1:a0:6b:d1:d2:00:00:00:01:1e:a5"
      cert_thumbprint     = "CAF7258E6FD87AB9B230409C8A8C06AEDDF65DF6"
      cert_valid_from     = "2026-05-17"
      cert_valid_to       = "2026-05-20"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:1e:a5:f3:d1:57:f1:a0:6b:d1:d2:00:00:00:01:1e:a5"
      )
}
