import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330007071EFE69BB502E196C7A00000007071E {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-21"
      version             = "1.0"

      hash                = "d734a6cabf906ee6ca934e2b16ac65c42b44e24d232fec469e0c3c3a1239afc5"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = "Fake AI applications targeting crypto users worldwide"

      signer              = "Marni Hirschorn"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:07:1e:fe:69:bb:50:2e:19:6c:7a:00:00:00:07:07:1e"
      cert_thumbprint     = "677E00A19E24D91C3797496E7195F025123795EB"
      cert_valid_from     = "2026-02-21"
      cert_valid_to       = "2026-02-24"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:07:1e:fe:69:bb:50:2e:19:6c:7a:00:00:00:07:07:1e"
      )
}
