import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330000D8896ECB1C18595946FD00000000D889 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-06"
      version             = "1.0"

      hash                = "aea6681137f7b0e95575d04e0f85f3ce5a4e4c1d92b1c79eaed9163541d25322"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: elvaronexkas[.]com"

      signer              = "Nicky Jaramillo Jr"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:d8:89:6e:cb:1c:18:59:59:46:fd:00:00:00:00:d8:89"
      cert_thumbprint     = "13611A9ABCAF87F27C308DFA6546D915729DA4F1"
      cert_valid_from     = "2026-05-06"
      cert_valid_to       = "2026-05-09"

      country             = "US"
      state               = "Washington"
      locality            = "Milton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:d8:89:6e:cb:1c:18:59:59:46:fd:00:00:00:00:d8:89"
      )
}
