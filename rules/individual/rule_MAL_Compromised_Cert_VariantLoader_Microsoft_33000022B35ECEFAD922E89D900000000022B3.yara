import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_33000022B35ECEFAD922E89D900000000022B3 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-16"
      version             = "1.0"

      hash                = "69872342a83b69b53a109575499a572ebf8979541f1a97822f4fadffcefa35fc"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 185.219.83.191"

      signer              = "TREY TROTTER"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:22:b3:5e:ce:fa:d9:22:e8:9d:90:00:00:00:00:22:b3"
      cert_thumbprint     = "6964F70C02B60FD831EC456F91468A0C3354A7E7"
      cert_valid_from     = "2026-04-16"
      cert_valid_to       = "2026-04-19"

      country             = "US"
      state               = "Oklahoma"
      locality            = "PONCA CITY"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:22:b3:5e:ce:fa:d9:22:e8:9d:90:00:00:00:00:22:b3"
      )
}
