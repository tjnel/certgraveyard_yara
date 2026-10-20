import "pe"

rule MAL_Compromised_Cert_Cloudhaze_Microsoft_330004252C9B0A92CA2B28637D00000004252C {
   meta:
      description         = "Detects Cloudhaze with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-01"
      version             = "1.0"

      hash                = "234d8d99629d1dcf9d74b0f9911af86548ff8a2a1bfcaf07a73d80491e53fdd5"
      malware             = "Cloudhaze"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PULSE TECH INC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:04:25:2c:9b:0a:92:ca:2b:28:63:7d:00:00:00:04:25:2c"
      cert_thumbprint     = "4c42ede35a9c6134da0af8b41ccb2dfed5999174"
      cert_valid_from     = "2026-08-01"
      cert_valid_to       = "2026-08-04"

      country             = "US"
      state               = "California"
      locality            = "West Hollywood"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:04:25:2c:9b:0a:92:ca:2b:28:63:7d:00:00:00:04:25:2c"
      )
}
