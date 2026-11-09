import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Certum_7CE7A642BF5EFBED33B9092AB3F479EB {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "4447a7c59c27fcf169ea49a5000749aa6e87f753dba9bf03b26f95538b2185e0"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "儋州森珀网络科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "7c:e7:a6:42:bf:5e:fb:ed:33:b9:09:2a:b3:f4:79:eb"
      cert_thumbprint     = "c9846658605ac4028cd447c116be0dc8cdd90236"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2027-03-23"

      country             = "CN"
      state               = "海南"
      locality            = "儋州"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "7c:e7:a6:42:bf:5e:fb:ed:33:b9:09:2a:b3:f4:79:eb"
      )
}
