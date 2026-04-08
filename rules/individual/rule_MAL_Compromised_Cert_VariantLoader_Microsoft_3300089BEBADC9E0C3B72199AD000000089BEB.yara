import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_3300089BEBADC9E0C3B72199AD000000089BEB {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-30"
      version             = "1.0"

      hash                = "8f18c0411cea16c7b037582ec485ccb8cb8afbb48ba71608761fe1f4bb98433e"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 188.137.241.213"

      signer              = "WILLIAM LAWLER"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:9b:eb:ad:c9:e0:c3:b7:21:99:ad:00:00:00:08:9b:eb"
      cert_thumbprint     = "F417305CDCD52597BF8AF461783112D96B7C9175"
      cert_valid_from     = "2026-03-30"
      cert_valid_to       = "2026-04-02"

      country             = "US"
      state               = "California"
      locality            = "ACTON"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:9b:eb:ad:c9:e0:c3:b7:21:99:ad:00:00:00:08:9b:eb"
      )
}
