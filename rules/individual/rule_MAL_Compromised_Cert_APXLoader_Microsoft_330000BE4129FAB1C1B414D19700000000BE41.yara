import "pe"

rule MAL_Compromised_Cert_APXLoader_Microsoft_330000BE4129FAB1C1B414D19700000000BE41 {
   meta:
      description         = "Detects APXLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-04"
      version             = "1.0"

      hash                = "69eaaa0e2f0b414b96b50b088d978cfe56a074a626d7179a67a5ee02b1830662"
      malware             = "APXLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Minh Tran"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:be:41:29:fa:b1:c1:b4:14:d1:97:00:00:00:00:be:41"
      cert_thumbprint     = "BA42908FAC35DC94F72FE80C84837A1B9777B2B6"
      cert_valid_from     = "2026-05-04"
      cert_valid_to       = "2026-05-07"

      country             = "US"
      state               = "Texas"
      locality            = "Grand Prairie"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:be:41:29:fa:b1:c1:b4:14:d1:97:00:00:00:00:be:41"
      )
}
