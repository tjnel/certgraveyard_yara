import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330007C40A6B2924C691CE681A00000007C40A {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "555f42c53dfd9c633f242ef3baca797365c2daee9af2475db2171d6fc2cd2b57"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Stalin Fabrico Loor Romero"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:c4:0a:6b:29:24:c6:91:ce:68:1a:00:00:00:07:c4:0a"
      cert_thumbprint     = "0C603F309C42F53F76AF83DF3576A9B9F2D8EAB1"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2026-04-04"

      country             = "US"
      state               = "Texas"
      locality            = "Richmond"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:c4:0a:6b:29:24:c6:91:ce:68:1a:00:00:00:07:c4:0a"
      )
}
