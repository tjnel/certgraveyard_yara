import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000126ABA61EE120CD7D0C500000000126AB {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-19"
      version             = "1.0"

      hash                = "b13d1d3aa9a98b6ba031e860b8802ad57960db0ec51213d93aa8a905abf85440"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chaunesey Morrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:26:ab:a6:1e:e1:20:cd:7d:0c:50:00:00:00:01:26:ab"
      cert_thumbprint     = "A18CA751DF7779462E600F38C17E08C584A258BD"
      cert_valid_from     = "2026-05-19"
      cert_valid_to       = "2026-05-22"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:26:ab:a6:1e:e1:20:cd:7d:0c:50:00:00:00:01:26:ab"
      )
}
