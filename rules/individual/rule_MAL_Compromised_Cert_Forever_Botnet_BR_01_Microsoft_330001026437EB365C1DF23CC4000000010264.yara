import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330001026437EB365C1DF23CC4000000010264 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-14"
      version             = "1.0"

      hash                = "a2167bd258c1dae2001aa41cd1cf8ab9debd427301656e21512197b045d729b0"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:01:02:64:37:eb:36:5c:1d:f2:3c:c4:00:00:00:01:02:64"
      cert_thumbprint     = "BAD0C26C9B13237547B413B244E02E33B56A00D7"
      cert_valid_from     = "2026-05-14"
      cert_valid_to       = "2026-05-17"

      country             = "DK"
      state               = "Central Jutland"
      locality            = "Hammel"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:01:02:64:37:eb:36:5c:1d:f2:3c:c4:00:00:00:01:02:64"
      )
}
