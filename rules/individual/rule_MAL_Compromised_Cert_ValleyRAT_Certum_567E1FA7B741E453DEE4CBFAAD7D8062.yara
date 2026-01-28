import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_567E1FA7B741E453DEE4CBFAAD7D8062 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-02"
      version             = "1.0"

      hash                = "097b38cef99feeb4d5acc40f6c204d83b49a1a4550038b88fd3572bd6c082be9"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Yangzhou Dadaxing Internet Information Service Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "56:7e:1f:a7:b7:41:e4:53:de:e4:cb:fa:ad:7d:80:62"
      cert_thumbprint     = "4B1801DCD2C66936ADBBE424D702B877B38D7F36"
      cert_valid_from     = "2025-09-02"
      cert_valid_to       = "2026-09-02"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Yangzhou"
      email               = "???"
      rdn_serial_number   = "91321002MAEM2JJP0Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "56:7e:1f:a7:b7:41:e4:53:de:e4:cb:fa:ad:7d:80:62"
      )
}
