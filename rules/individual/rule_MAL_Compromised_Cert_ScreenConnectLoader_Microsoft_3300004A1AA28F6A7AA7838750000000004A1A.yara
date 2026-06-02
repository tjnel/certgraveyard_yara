import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300004A1AA28F6A7AA7838750000000004A1A {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-13"
      version             = "1.0"

      hash                = "024c5039cb69288955269253d845f87ed495bd6163392e0426d5780970786b48"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:4a:1a:a2:8f:6a:7a:a7:83:87:50:00:00:00:00:4a:1a"
      cert_thumbprint     = "5EA715F74A23DE32F4797304C0F24A21AE4E2BDE"
      cert_valid_from     = "2026-04-13"
      cert_valid_to       = "2026-04-16"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:4a:1a:a2:8f:6a:7a:a7:83:87:50:00:00:00:00:4a:1a"
      )
}
