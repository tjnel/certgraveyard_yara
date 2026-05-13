import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Microsoft_330000D4903D6B02DB936F150100000000D490 {
   meta:
      description         = "Detects Certificate warming with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-09"
      version             = "1.0"

      hash                = "2c38a3a0ffada9e1b029df2d22551c340f9dd67b7e7d2aab9bd293cdd602846e"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = "This file is benign but is being signed to increase trust in the certificate."

      signer              = "MARKE SOLUTIONS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:d4:90:3d:6b:02:db:93:6f:15:01:00:00:00:00:d4:90"
      cert_thumbprint     = "F18246DE9A62E236242E5EDB2BEA1D63FFCAC1F8"
      cert_valid_from     = "2026-05-09"
      cert_valid_to       = "2026-05-12"

      country             = "GB"
      state               = "Warwickshire"
      locality            = "ALCESTER"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:d4:90:3d:6b:02:db:93:6f:15:01:00:00:00:00:d4:90"
      )
}
