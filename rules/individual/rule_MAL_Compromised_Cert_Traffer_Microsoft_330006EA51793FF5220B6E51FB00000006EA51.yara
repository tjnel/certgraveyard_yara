import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_330006EA51793FF5220B6E51FB00000006EA51 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-02"
      version             = "1.0"

      hash                = "4990878b7ee547b3bb4678aaf83f9b2036d7661fa19b5cfa5f1765f3d4fec097"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:ea:51:79:3f:f5:22:0b:6e:51:fb:00:00:00:06:ea:51"
      cert_thumbprint     = "D2B431F77BFC43DE62BE20444DC5ADC612624379"
      cert_valid_from     = "2026-01-02"
      cert_valid_to       = "2026-01-05"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:ea:51:79:3f:f5:22:0b:6e:51:fb:00:00:00:06:ea:51"
      )
}
