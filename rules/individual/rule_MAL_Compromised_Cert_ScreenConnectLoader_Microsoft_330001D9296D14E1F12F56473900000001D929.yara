import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001D9296D14E1F12F56473900000001D929 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-08"
      version             = "1.0"

      hash                = "01f8832e1da252782190d58b1d4ed7cebb9c6dade34ca58dd19eebd5e537d604"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Kimberly Love"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:01:d9:29:6d:14:e1:f1:2f:56:47:39:00:00:00:01:d9:29"
      cert_thumbprint     = "8FF32A2F092A1DF0188D3964F616C4A99921395A"
      cert_valid_from     = "2026-06-08"
      cert_valid_to       = "2026-06-11"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:01:d9:29:6d:14:e1:f1:2f:56:47:39:00:00:00:01:d9:29"
      )
}
