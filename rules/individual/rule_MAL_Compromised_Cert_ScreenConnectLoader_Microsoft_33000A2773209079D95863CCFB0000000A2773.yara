import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000A2773209079D95863CCFB0000000A2773 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-31"
      version             = "1.0"

      hash                = "9168048ae4f5b45d70eb44904b70b1757faf039001cd16e463ca2b49b297d25b"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ITTC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:0a:27:73:20:90:79:d9:58:63:cc:fb:00:00:00:0a:27:73"
      cert_thumbprint     = "b456b61e97c0fbee94fc47bfcbaf8d7bfceaa118"
      cert_valid_from     = "2026-10-31"
      cert_valid_to       = "2026-11-03"

      country             = "NL"
      state               = "Utrecht"
      locality            = "Urecht"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:0a:27:73:20:90:79:d9:58:63:cc:fb:00:00:00:0a:27:73"
      )
}
