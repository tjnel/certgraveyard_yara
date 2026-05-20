import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000128FA7E99282F7FFF914C0000000128FA {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-18"
      version             = "1.0"

      hash                = "b7b178c9cab101fa1158a1f372decb7a1722fdf3f84a93e83fc6f69c6a1e7544"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chaunesey Morrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:28:fa:7e:99:28:2f:7f:ff:91:4c:00:00:00:01:28:fa"
      cert_thumbprint     = "4287CBD6E59A1B3DC762F2366BA29FCAB1F9A03F"
      cert_valid_from     = "2026-05-18"
      cert_valid_to       = "2026-05-21"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:28:fa:7e:99:28:2f:7f:ff:91:4c:00:00:00:01:28:fa"
      )
}
