import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330001C1A1C7BC994094C9C2B300000001C1A1 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-06"
      version             = "1.0"

      hash                = "b79566fad4e74019eb321b6f4df3c567caad2b1debd78091e925d3dfac90569b"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Elusive Techno"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:01:c1:a1:c7:bc:99:40:94:c9:c2:b3:00:00:00:01:c1:a1"
      cert_thumbprint     = "185A94282E7B68D28045913BD8527CC0CA56C856"
      cert_valid_from     = "2026-06-06"
      cert_valid_to       = "2026-06-09"

      country             = "NL"
      state               = "Groningen"
      locality            = "Groningen"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:01:c1:a1:c7:bc:99:40:94:c9:c2:b3:00:00:00:01:c1:a1"
      )
}
