import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330007AFEEA2D4B5F7A7BA551200000007AFEE {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-12"
      version             = "1.0"

      hash                = "53d7694d8dc639bc2fb11d2aaf75193d6b7a215d80b1ac56bd12c26df72d9840"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DIGITAL ADVERTISING BUSINESS INFLUENCERS S.R.L."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:af:ee:a2:d4:b5:f7:a7:ba:55:12:00:00:00:07:af:ee"
      cert_thumbprint     = "EAAD96402A2C98AC6B9C95A889AC6CD1DF60F8BB"
      cert_valid_from     = "2026-02-12"
      cert_valid_to       = "2026-02-15"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:af:ee:a2:d4:b5:f7:a7:ba:55:12:00:00:00:07:af:ee"
      )
}
