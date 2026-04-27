import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300005148694B37DCDA9E19CE000000005148 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-19"
      version             = "1.0"

      hash                = "e43ba5bfa5302cc7e0006e2ae6cfea8a472678858410d190f98e15babe84ded5"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:51:48:69:4b:37:dc:da:9e:19:ce:00:00:00:00:51:48"
      cert_thumbprint     = "FD7D7B68479230B404E86518729666C31594AB09"
      cert_valid_from     = "2026-04-19"
      cert_valid_to       = "2026-04-22"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:51:48:69:4b:37:dc:da:9e:19:ce:00:00:00:00:51:48"
      )
}
