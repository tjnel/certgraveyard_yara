import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001984FEB3E194FF4551C6F00000001984F {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-02"
      version             = "1.0"

      hash                = "b461e9b830451662c542ee2db836b97e4f75604370eea8d0965082bd7d3bb5ae"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Paula Foster"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:98:4f:eb:3e:19:4f:f4:55:1c:6f:00:00:00:01:98:4f"
      cert_thumbprint     = "CBCDCA10BDF7A8161E0A1F1BC96320D0FE54BCA2"
      cert_valid_from     = "2026-06-02"
      cert_valid_to       = "2026-06-05"

      country             = "US"
      state               = "fl"
      locality            = "Saint James City"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:98:4f:eb:3e:19:4f:f4:55:1c:6f:00:00:00:01:98:4f"
      )
}
