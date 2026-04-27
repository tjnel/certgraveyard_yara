import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300005E046E3329FE185C4715000000005E04 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-20"
      version             = "1.0"

      hash                = "5051350c1c2058d7ad4cd95c40219c68bc559fcb15434a688b88672dd376bd13"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:5e:04:6e:33:29:fe:18:5c:47:15:00:00:00:00:5e:04"
      cert_thumbprint     = "4787FEC48F672F6D4587BD6C8F3781C79E8C4514"
      cert_valid_from     = "2026-04-20"
      cert_valid_to       = "2026-04-23"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:5e:04:6e:33:29:fe:18:5c:47:15:00:00:00:00:5e:04"
      )
}
