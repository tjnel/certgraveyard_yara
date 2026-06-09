import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001BF9DE4F0EA4ABA4E192200000001BF9D {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-06"
      version             = "1.0"

      hash                = "60f104030a7e6fc47d5ce7c286c5172e9f835a09b5a560350ac71d0c25f8c187"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Paula Foster"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:bf:9d:e4:f0:ea:4a:ba:4e:19:22:00:00:00:01:bf:9d"
      cert_thumbprint     = "089D44F17F17B3AFF91342CD8D5E880E62590C34"
      cert_valid_from     = "2026-06-06"
      cert_valid_to       = "2026-06-09"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:bf:9d:e4:f0:ea:4a:ba:4e:19:22:00:00:00:01:bf:9d"
      )
}
