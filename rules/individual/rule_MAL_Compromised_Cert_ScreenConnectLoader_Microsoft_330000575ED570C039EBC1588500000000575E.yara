import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000575ED570C039EBC1588500000000575E {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-14"
      version             = "1.0"

      hash                = "af521794c124350f97d719b0892e8ac2c932b03b895b50293b600f765ad58260"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:57:5e:d5:70:c0:39:eb:c1:58:85:00:00:00:00:57:5e"
      cert_thumbprint     = "DF13E386C60AABEE8EC4F14124B7AC251EDA7F1A"
      cert_valid_from     = "2026-04-14"
      cert_valid_to       = "2026-04-17"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:57:5e:d5:70:c0:39:eb:c1:58:85:00:00:00:00:57:5e"
      )
}
