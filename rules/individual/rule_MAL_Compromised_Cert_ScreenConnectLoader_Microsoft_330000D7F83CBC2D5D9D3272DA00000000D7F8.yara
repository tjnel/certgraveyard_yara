import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000D7F83CBC2D5D9D3272DA00000000D7F8 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-06"
      version             = "1.0"

      hash                = "40a12372d27db4939d748357f2cdca526c71da11ecc893ba115556ccf5118332"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CHRISTIAN TORRES"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:d7:f8:3c:bc:2d:5d:9d:32:72:da:00:00:00:00:d7:f8"
      cert_thumbprint     = "30B63B62CDCC40D85623F5C9CF1E31CE4DB4B7C3"
      cert_valid_from     = "2026-05-06"
      cert_valid_to       = "2026-05-09"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:d7:f8:3c:bc:2d:5d:9d:32:72:da:00:00:00:00:d7:f8"
      )
}
