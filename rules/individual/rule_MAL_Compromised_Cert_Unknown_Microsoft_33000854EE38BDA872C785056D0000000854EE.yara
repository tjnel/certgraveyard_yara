import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_33000854EE38BDA872C785056D0000000854EE {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-12"
      version             = "1.0"

      hash                = "91fc3bf4caf5d6014b1f344b865ab1e063d6a7e9acf5705ad7ced4df91620771"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ISABEL ALEJANDRA FLORES"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:08:54:ee:38:bd:a8:72:c7:85:05:6d:00:00:00:08:54:ee"
      cert_thumbprint     = "eb945b5baad995febe5de6d7586127f83ad0229e"
      cert_valid_from     = "2026-10-12"
      cert_valid_to       = "2026-10-15"

      country             = "US"
      state               = "in"
      locality            = "East Chicago"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:08:54:ee:38:bd:a8:72:c7:85:05:6d:00:00:00:08:54:ee"
      )
}
