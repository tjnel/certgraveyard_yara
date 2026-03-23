import "pe"

rule MAL_Compromised_Cert_FakeMSTeams_Microsoft_3300078738DC02A68CB93FC81D000000078738 {
   meta:
      description         = "Detects FakeMSTeams with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-20"
      version             = "1.0"

      hash                = "ae2a58bc0684dbcd69ae0690f09de74538ce8764a9d21f463f3c1fafd03622c2"
      malware             = "FakeMSTeams"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mariah Lingle"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:87:38:dc:02:a6:8c:b9:3f:c8:1d:00:00:00:07:87:38"
      cert_thumbprint     = "CB6DA4D566999EB64CC4266AA3BB37FB8A1CD75B"
      cert_valid_from     = "2026-03-20"
      cert_valid_to       = "2026-03-23"

      country             = "US"
      state               = "Montana"
      locality            = "Columbia Fals"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:87:38:dc:02:a6:8c:b9:3f:c8:1d:00:00:00:07:87:38"
      )
}
