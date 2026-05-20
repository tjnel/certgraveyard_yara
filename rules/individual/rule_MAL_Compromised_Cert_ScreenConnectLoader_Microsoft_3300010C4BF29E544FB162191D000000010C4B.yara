import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300010C4BF29E544FB162191D000000010C4B {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-15"
      version             = "1.0"

      hash                = "25bba86ff3edca498fa4e6d69bad0cbeb4c2e4f2503bde15c4eed7cc2a34c7bf"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chaunesey Morrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:0c:4b:f2:9e:54:4f:b1:62:19:1d:00:00:00:01:0c:4b"
      cert_thumbprint     = "789A670AC35FD0E43B0CAAAEDB8E205BE00A3404"
      cert_valid_from     = "2026-05-15"
      cert_valid_to       = "2026-05-18"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:0c:4b:f2:9e:54:4f:b1:62:19:1d:00:00:00:01:0c:4b"
      )
}
