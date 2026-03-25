import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330008A2D1467FAF446BA206DA00000008A2D1 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-22"
      version             = "1.0"

      hash                = "1e1883289ec619ae7d2b60e1b85e032a29f14401d1108cc9918bdef390940c4c"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mariah Lingle"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:a2:d1:46:7f:af:44:6b:a2:06:da:00:00:00:08:a2:d1"
      cert_thumbprint     = "223D7EAD695023490C85C60A888DB19A9ABD0AF7"
      cert_valid_from     = "2026-03-22"
      cert_valid_to       = "2026-03-25"

      country             = "US"
      state               = "Montana"
      locality            = "Columbia Fals"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:a2:d1:46:7f:af:44:6b:a2:06:da:00:00:00:08:a2:d1"
      )
}
