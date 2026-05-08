import "pe"

rule MAL_Compromised_Cert_APXLoader_Microsoft_33000059130546DBB59522E267000000005913 {
   meta:
      description         = "Detects APXLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-20"
      version             = "1.0"

      hash                = "d56b30a373b68dbba914fd63ae619565c51ad94a7865d64584ab425343b4a107"
      malware             = "APXLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "Phillips Mcwilliams"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:59:13:05:46:db:b5:95:22:e2:67:00:00:00:00:59:13"
      cert_thumbprint     = "463651FD85F0BE1A0D0836558608CB0149216B20"
      cert_valid_from     = "2026-04-20"
      cert_valid_to       = "2026-04-23"

      country             = "US"
      state               = "South Carolina"
      locality            = "Columbia"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:59:13:05:46:db:b5:95:22:e2:67:00:00:00:00:59:13"
      )
}
