import "pe"

rule MAL_Compromised_Cert_FakeAITrading_Verokey_E05254FCB9EA1E9770852E540ED6AE8 {
   meta:
      description         = "Detects FakeAITrading with compromised cert (Verokey)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-13"
      version             = "1.0"

      hash                = "a34d7aaf4a68f906dfaf1e5ce29c92c512e44aff94ca1e19f5542ac7fb3f357d"
      malware             = "FakeAITrading"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "温江区明宇网络技术服务工作室"
      cert_issuer_short   = "Verokey"
      cert_issuer         = "Verokey Secure Code"
      cert_serial         = "e0:52:54:fc:b9:ea:1e:97:70:85:2e:54:0e:d6:ae:8"
      cert_thumbprint     = "92f6f5fe1c5bc84cc704f79179a09e6083385d4d"
      cert_valid_from     = "2025-10-13"
      cert_valid_to       = "2029-01-08"

      country             = "CN"
      state               = "四川省"
      locality            = "成都市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Verokey Secure Code" and
         sig.serial == "e0:52:54:fc:b9:ea:1e:97:70:85:2e:54:0e:d6:ae:8"
      )
}
