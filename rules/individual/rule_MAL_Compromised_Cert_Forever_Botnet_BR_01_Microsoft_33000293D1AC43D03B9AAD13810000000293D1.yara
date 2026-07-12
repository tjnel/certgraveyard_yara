import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_33000293D1AC43D03B9AAD13810000000293D1 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-01"
      version             = "1.0"

      hash                = "3600a7ce118dbf9950ac2734abcb8648408b3638085397b94e0c19c193cae3b4"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "Xryus Technologies LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:02:93:d1:ac:43:d0:3b:9a:ad:13:81:00:00:00:02:93:d1"
      cert_thumbprint     = "6017ADAC0F83566A455B25095BF9D29F18968B05"
      cert_valid_from     = "2026-07-01"
      cert_valid_to       = "2026-07-04"

      country             = "US"
      state               = "Delaware"
      locality            = "Lewes"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:02:93:d1:ac:43:d0:3b:9a:ad:13:81:00:00:00:02:93:d1"
      )
}
