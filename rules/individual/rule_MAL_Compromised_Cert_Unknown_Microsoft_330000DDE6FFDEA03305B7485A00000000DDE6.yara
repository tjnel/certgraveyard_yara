import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330000DDE6FFDEA03305B7485A00000000DDE6 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-10"
      version             = "1.0"

      hash                = "e1f179df4b7c946e7161d61da71c136c2ddd203434f6cd926556894b48c712ea"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:dd:e6:ff:de:a0:33:05:b7:48:5a:00:00:00:00:dd:e6"
      cert_thumbprint     = "42179A86E7A001E762D54E03EAF515838ABDDB6A"
      cert_valid_from     = "2026-05-10"
      cert_valid_to       = "2026-05-13"

      country             = "DK"
      state               = "Central Jutland"
      locality            = "Hammel"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:dd:e6:ff:de:a0:33:05:b7:48:5a:00:00:00:00:dd:e6"
      )
}
