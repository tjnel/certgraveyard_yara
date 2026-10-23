import "pe"

rule MAL_Compromised_Cert_Unknown_RAT_Certum_74FB595ABCAEE8784E0437B3B0CB6A5C {
   meta:
      description         = "Detects Unknown RAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-03"
      version             = "1.0"

      hash                = "e34942601a91672eb0c9895b5a7a71dd4d7ef19acee1e2d6ec85834549b850f8"
      malware             = "Unknown RAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "ZhongHaiCheng"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "74:fb:59:5a:bc:ae:e8:78:4e:04:37:b3:b0:cb:6a:5c"
      cert_thumbprint     = "32c273cac8e320f235575851c489f6067b4cd4b5"
      cert_valid_from     = "2026-08-03"
      cert_valid_to       = "2027-08-03"

      country             = "CN"
      state               = "江西省"
      locality            = "赣州市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "74:fb:59:5a:bc:ae:e8:78:4e:04:37:b3:b0:cb:6a:5c"
      )
}
