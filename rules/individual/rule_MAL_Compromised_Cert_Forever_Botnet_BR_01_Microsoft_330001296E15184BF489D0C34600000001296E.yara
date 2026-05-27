import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330001296E15184BF489D0C34600000001296E {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-19"
      version             = "1.0"

      hash                = "70f8889bfa65464908e36fb4687d9385dff1f89cb2e67106dba3c722fb97eda8"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:01:29:6e:15:18:4b:f4:89:d0:c3:46:00:00:00:01:29:6e"
      cert_thumbprint     = "FBA76E084603A363932244A6EA9E655C0C3B2AD6"
      cert_valid_from     = "2026-05-19"
      cert_valid_to       = "2026-05-22"

      country             = "DK"
      state               = "Central Jutland"
      locality            = "Hammel"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:01:29:6e:15:18:4b:f4:89:d0:c3:46:00:00:00:01:29:6e"
      )
}
