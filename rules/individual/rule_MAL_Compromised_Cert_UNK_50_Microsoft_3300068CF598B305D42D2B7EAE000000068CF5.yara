import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300068CF598B305D42D2B7EAE000000068CF5 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-19"
      version             = "1.0"

      hash                = "653c6ca37e2b299b2d4609e06d08cc0a8459c30d87a0ff0bdfcffac581622abb"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DIGITAL ADVERTISING BUSINESS INFLUENCERS S.R.L."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:06:8c:f5:98:b3:05:d4:2d:2b:7e:ae:00:00:00:06:8c:f5"
      cert_thumbprint     = "660DBB5AF5150413D8D5853CCEE37C4C6D5DAB76"
      cert_valid_from     = "2026-01-19"
      cert_valid_to       = "2026-01-22"

      country             = "RO"
      state               = "Brasov"
      locality            = "Brasov"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:06:8c:f5:98:b3:05:d4:2d:2b:7e:ae:00:00:00:06:8c:f5"
      )
}
