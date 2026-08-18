import "pe"

rule MAL_Compromised_Cert_ScreenConnect_Loader_Microsoft_330008F14B653BF56DB14D28A300000008F14B {
   meta:
      description         = "Detects ScreenConnect Loader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-05"
      version             = "1.0"

      hash                = "43541ea474820a8dbb6c5c40121d74caa8ee4566cd0293775fbed6631f6f9d12"
      malware             = "ScreenConnect Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DAWN RENEE"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:f1:4b:65:3b:f5:6d:b1:4d:28:a3:00:00:00:08:f1:4b"
      cert_thumbprint     = "f35658413600d8a73c2a642497fe9be3b5948a2e"
      cert_valid_from     = "2026-04-05"
      cert_valid_to       = "2026-04-08"

      country             = "US"
      state               = "Hawaii"
      locality            = "KULA"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:f1:4b:65:3b:f5:6d:b1:4d:28:a3:00:00:00:08:f1:4b"
      )
}
