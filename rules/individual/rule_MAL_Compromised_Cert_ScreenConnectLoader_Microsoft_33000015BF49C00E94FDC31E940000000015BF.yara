import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000015BF49C00E94FDC31E940000000015BF {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-14"
      version             = "1.0"

      hash                = "60ddfc25ccc4cf804a4225cbb4e33548cb4e0d2b1334e9916e083914926ba874"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Perry Sabrina Ann"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:15:bf:49:c0:0e:94:fd:c3:1e:94:00:00:00:00:15:bf"
      cert_thumbprint     = "700367DC5F5CE0A7874F9ECFB4101D4EE1CBBBEE"
      cert_valid_from     = "2026-04-14"
      cert_valid_to       = "2026-04-17"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:15:bf:49:c0:0e:94:fd:c3:1e:94:00:00:00:00:15:bf"
      )
}
