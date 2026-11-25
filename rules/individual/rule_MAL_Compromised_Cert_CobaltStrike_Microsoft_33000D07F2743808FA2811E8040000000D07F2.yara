import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Microsoft_33000D07F2743808FA2811E8040000000D07F2 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-23"
      version             = "1.0"

      hash                = "0c3afb30eca4de018a7a3aa42ab43acc4a3c998595ba1802da876feffb419bcc"
      malware             = "CobaltStrike"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ISABEL ALEJANDRA FLORES"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:0d:07:f2:74:38:08:fa:28:11:e8:04:00:00:00:0d:07:f2"
      cert_thumbprint     = "aae6b6cca9e4872d6bd9d092a26bf62a415ee740"
      cert_valid_from     = "2026-11-23"
      cert_valid_to       = "2026-11-26"

      country             = "US"
      state               = "in"
      locality            = "East Chicago"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:0d:07:f2:74:38:08:fa:28:11:e8:04:00:00:00:0d:07:f2"
      )
}
