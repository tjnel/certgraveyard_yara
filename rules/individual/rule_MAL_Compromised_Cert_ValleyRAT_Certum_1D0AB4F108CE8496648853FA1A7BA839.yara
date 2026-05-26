import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_1D0AB4F108CE8496648853FA1A7BA839 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-06"
      version             = "1.0"

      hash                = "e4439550ecd97e0f734a8d2fc79216bbbb91f5e0a776d9712e2970cc12c7436b"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuhan Quesangweng Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "1d:0a:b4:f1:08:ce:84:96:64:88:53:fa:1a:7b:a8:39"
      cert_thumbprint     = "E0850B39B69DDAA0CC604E54BAABD03D6FF16A09"
      cert_valid_from     = "2026-03-06"
      cert_valid_to       = "2027-03-06"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "1d:0a:b4:f1:08:ce:84:96:64:88:53:fa:1a:7b:a8:39"
      )
}
