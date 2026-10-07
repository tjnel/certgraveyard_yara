import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330007732B49D178A64025EF6700000007732B {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-02"
      version             = "1.0"

      hash                = "40ac4220748b54e62402fd428b76ce7467e3ee96af7375b13953ad188f42fc92"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ashley Marie Boynton"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:07:73:2b:49:d1:78:a6:40:25:ef:67:00:00:00:07:73:2b"
      cert_thumbprint     = "d2802e12bfb8923658d88e175c0aeda070a7112c"
      cert_valid_from     = "2026-10-02"
      cert_valid_to       = "2026-10-05"

      country             = "US"
      state               = "nv"
      locality            = "SPARKS"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:07:73:2b:49:d1:78:a6:40:25:ef:67:00:00:00:07:73:2b"
      )
}
