import "pe"

rule MAL_Compromised_Cert_FakeTrading_Microsoft_330000EBF2267F501774231D3600000000EBF2 {
   meta:
      description         = "Detects FakeTrading with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-09"
      version             = "1.0"

      hash                = "c68c7a04aab27cc5bc39ed5f98f41ad3a0a6cb93f1b99288400cdc9d68afea88"
      malware             = "FakeTrading"
      malware_type        = "Unknown"
      malware_notes       = "Fake TradingView loading further payloads from 212.86.114.171/webdav/update.dat"

      signer              = "A&A Interactive Media Group"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:eb:f2:26:7f:50:17:74:23:1d:36:00:00:00:00:eb:f2"
      cert_thumbprint     = "98C2DFD4E2533D1492CE12E279509F8865B304E0"
      cert_valid_from     = "2026-05-09"
      cert_valid_to       = "2026-05-12"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:eb:f2:26:7f:50:17:74:23:1d:36:00:00:00:00:eb:f2"
      )
}
