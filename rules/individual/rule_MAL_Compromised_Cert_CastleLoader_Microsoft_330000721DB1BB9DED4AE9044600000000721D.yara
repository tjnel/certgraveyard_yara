import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330000721DB1BB9DED4AE9044600000000721D {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-23"
      version             = "1.0"

      hash                = "0dc0e160c1898c94e4cbda8d2a6b4d8334a423894cb1e5838195b905f22fdda4"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: bmwservicebestik[.]com"

      signer              = "SHYANNE COLLINS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:72:1d:b1:bb:9d:ed:4a:e9:04:46:00:00:00:00:72:1d"
      cert_thumbprint     = "3795A3BC5A8145744E31C90039F19BEBFD0AA841"
      cert_valid_from     = "2026-04-23"
      cert_valid_to       = "2026-04-26"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:72:1d:b1:bb:9d:ed:4a:e9:04:46:00:00:00:00:72:1d"
      )
}
