import "pe"

rule MAL_Compromised_Cert_QuasarRAT_Certum_621BB34996258258F752A174D473FE1D {
   meta:
      description         = "Detects QuasarRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "7ac7d052157b22283619e84a8a435788af0d21f714b3615bd523187dc6601f50"
      malware             = "QuasarRAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "北京谷云达吉商贸有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "62:1b:b3:49:96:25:82:58:f7:52:a1:74:d4:73:fe:1d"
      cert_thumbprint     = "833FE45D0B7310E85A523BBD8C59F1A19DD52B5D"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2026-10-30"

      country             = "CN"
      state               = "北京市"
      locality            = "北京市"
      email               = "???"
      rdn_serial_number   = "91110112MAENGGCR13"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "62:1b:b3:49:96:25:82:58:f7:52:a1:74:d4:73:fe:1d"
      )
}
