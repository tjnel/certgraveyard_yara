import "pe"

rule MAL_Compromised_Cert_HijackLoader_Certum_1585C2EDD17BB80BC7DE15448CF4792D {
   meta:
      description         = "Detects HijackLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-29"
      version             = "1.0"

      hash                = "02cbc77d52e12aea6a6c9db36c07d2eccd1af9d39b88b3802b40cb10d088b30c"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "广州杜倾科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "15:85:c2:ed:d1:7b:b8:0b:c7:de:15:44:8c:f4:79:2d"
      cert_thumbprint     = "FF9EDC0945E422BEF39C9B2F521F5BCA7A382951"
      cert_valid_from     = "2026-01-29"
      cert_valid_to       = "2027-01-29"

      country             = "CN"
      state               = "广东"
      locality            = "广州"
      email               = "???"
      rdn_serial_number   = "91440106MAEJYFQT9N"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "15:85:c2:ed:d1:7b:b8:0b:c7:de:15:44:8c:f4:79:2d"
      )
}
