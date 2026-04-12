import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330007A2006AFF3E68DB3F14A500000007A200 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-26"
      version             = "1.0"

      hash                = "665c955e6ba4f0573e8ba10a48e0f6075b4cc026296233722849bc4fa1ef3e1a"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = "Fake cryptocurrency wallets builds leading to malicious RMM connections"

      signer              = "Perry Sabrina Ann"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:a2:00:6a:ff:3e:68:db:3f:14:a5:00:00:00:07:a2:00"
      cert_thumbprint     = "8E247C6F9A70C38FE9EB988C46A51D564CEAECCB"
      cert_valid_from     = "2026-03-26"
      cert_valid_to       = "2026-03-29"

      country             = "US"
      state               = "Hawaii"
      locality            = "Wailuku"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:a2:00:6a:ff:3e:68:db:3f:14:a5:00:00:00:07:a2:00"
      )
}
