import "pe"

rule MAL_Compromised_Cert_FakeImage_Microsoft_330001A978A8D1BA8AFF24C6CC00000001A978 {
   meta:
      description         = "Detects FakeImage with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-03"
      version             = "1.0"

      hash                = "7e50063146793a723b18bd5e926ac6fc80884f1cf18945caa5b483f8bddf8ab8"
      malware             = "FakeImage"
      malware_type        = "Unknown"
      malware_notes       = "C2: 210.16.65.98"

      signer              = "Elusive Techno"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:a9:78:a8:d1:ba:8a:ff:24:c6:cc:00:00:00:01:a9:78"
      cert_thumbprint     = "07D2888B6AEC2EAAADB093DC132AA78D78115110"
      cert_valid_from     = "2026-06-03"
      cert_valid_to       = "2026-06-06"

      country             = "NL"
      state               = "Groningen"
      locality            = "Groningen"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:a9:78:a8:d1:ba:8a:ff:24:c6:cc:00:00:00:01:a9:78"
      )
}
