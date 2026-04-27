import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300006AFD78815D7CD8EB8537000000006AFD {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-22"
      version             = "1.0"

      hash                = "a9e96c7fd61fc2ea26576ad6f0dfc36fceb795ebb60219e0e7aed689fe75b3c1"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:6a:fd:78:81:5d:7c:d8:eb:85:37:00:00:00:00:6a:fd"
      cert_thumbprint     = "D0A63A1D54A1823AA6005A3FFBD8AE850B6BD7A8"
      cert_valid_from     = "2026-04-22"
      cert_valid_to       = "2026-04-25"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:6a:fd:78:81:5d:7c:d8:eb:85:37:00:00:00:00:6a:fd"
      )
}
