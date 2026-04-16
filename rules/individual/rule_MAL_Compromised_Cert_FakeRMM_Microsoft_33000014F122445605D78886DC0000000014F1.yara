import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_33000014F122445605D78886DC0000000014F1 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-13"
      version             = "1.0"

      hash                = "2eac72a04860eb435310bf03ffbf475e5468b251b9eb5e0ae6fabd2d4ca3447e"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:14:f1:22:44:56:05:d7:88:86:dc:00:00:00:00:14:f1"
      cert_thumbprint     = "BD91F74285A5789002308A49FE9B29325DF462F2"
      cert_valid_from     = "2026-04-13"
      cert_valid_to       = "2026-04-16"

      country             = "US"
      state               = "Tennessee"
      locality            = "nashville"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:14:f1:22:44:56:05:d7:88:86:dc:00:00:00:00:14:f1"
      )
}
