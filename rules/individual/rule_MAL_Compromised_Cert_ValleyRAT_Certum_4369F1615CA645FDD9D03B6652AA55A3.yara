import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_4369F1615CA645FDD9D03B6652AA55A3 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-28"
      version             = "1.0"

      hash                = "ca47e13a2980817e7849ddfef70312542ed11efaeba7b1b583161c06a440baf2"
      malware             = "ValleyRAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Zhengzhou Xiaoye Network Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "43:69:f1:61:5c:a6:45:fd:d9:d0:3b:66:52:aa:55:a3"
      cert_thumbprint     = "4d398ec6f1cd4d00b3e35a85a8cf739b09b015de"
      cert_valid_from     = "2026-01-28"
      cert_valid_to       = "2027-01-28"

      country             = "CN"
      state               = "河南"
      locality            = "郑州"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "43:69:f1:61:5c:a6:45:fd:d9:d0:3b:66:52:aa:55:a3"
      )
}
