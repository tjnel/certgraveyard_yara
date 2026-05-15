import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000EAB27F72FC3927BE22B500000000EAB2 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-12"
      version             = "1.0"

      hash                = "5c3686bd7a02fbfd24a66ea5e1b9af0cf2b6ed76cbf09a14ccb9e3bb9954491b"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chaunesey Morrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:ea:b2:7f:72:fc:39:27:be:22:b5:00:00:00:00:ea:b2"
      cert_thumbprint     = "5862421BFD52F5065DF1FB14E775B4189F4CBB1A"
      cert_valid_from     = "2026-05-12"
      cert_valid_to       = "2026-05-15"

      country             = "US"
      state               = "Texas"
      locality            = "converse"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:ea:b2:7f:72:fc:39:27:be:22:b5:00:00:00:00:ea:b2"
      )
}
