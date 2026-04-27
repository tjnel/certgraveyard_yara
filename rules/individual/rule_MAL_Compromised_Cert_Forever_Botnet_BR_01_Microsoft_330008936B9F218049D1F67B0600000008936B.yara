import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330008936B9F218049D1F67B0600000008936B {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "34c578754cb2f08e5d8a5b02f1aeaa5d90ff3b566b9beae3a76ab77efb878194"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mariah Lingle"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:93:6b:9f:21:80:49:d1:f6:7b:06:00:00:00:08:93:6b"
      cert_thumbprint     = "B8AF9765B1FB1C2A703663E8C5D8A29622F94C2C"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2026-03-22"

      country             = "US"
      state               = "Montana"
      locality            = "Columbia Fals"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:93:6b:9f:21:80:49:d1:f6:7b:06:00:00:00:08:93:6b"
      )
}
