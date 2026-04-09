import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330008DCD7BAA40977D7FE5F0500000008DCD7 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-31"
      version             = "1.0"

      hash                = "8994d6ba13561a3fca2fca333213a65b7173103c646416508b6755d500ad52e1"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Stalin Fabrico Loor Romero"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:dc:d7:ba:a4:09:77:d7:fe:5f:05:00:00:00:08:dc:d7"
      cert_thumbprint     = "0E5369D8415E1B1CEE0A78DBB5A297E3ACF15AB2"
      cert_valid_from     = "2026-03-31"
      cert_valid_to       = "2026-04-03"

      country             = "US"
      state               = "Texas"
      locality            = "Richmond"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:dc:d7:ba:a4:09:77:d7:fe:5f:05:00:00:00:08:dc:d7"
      )
}
