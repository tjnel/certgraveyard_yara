import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330005D979322D82AB26D77E5700000005D979 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-18"
      version             = "1.0"

      hash                = "d113b09b5e34329277b9822c512ddadbc326d68f8aa4fa984cacb7c1f938701a"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SARTO THOMAS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:d9:79:32:2d:82:ab:26:d7:7e:57:00:00:00:05:d9:79"
      cert_thumbprint     = "7D5907F81391F5605730CBCAB53D876D8AA7ABEE"
      cert_valid_from     = "2025-12-18"
      cert_valid_to       = "2025-12-21"

      country             = "GB"
      state               = "Hampshire"
      locality            = "Whiteley"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:d9:79:32:2d:82:ab:26:d7:7e:57:00:00:00:05:d9:79"
      )
}
