import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330006C2036666AE6BA75FD63300000006C203 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-03"
      version             = "1.0"

      hash                = "d12df83cb84b0e9636148cfdae448152b87e54d68caf9f3c202c0b4a479fd9fc"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFTOLIO sp. z o.o."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:c2:03:66:66:ae:6b:a7:5f:d6:33:00:00:00:06:c2:03"
      cert_thumbprint     = "82F7E904F0C136239B7335D5F7E3AAA1223DC325"
      cert_valid_from     = "2026-01-03"
      cert_valid_to       = "2026-01-06"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:c2:03:66:66:ae:6b:a7:5f:d6:33:00:00:00:06:c2:03"
      )
}
