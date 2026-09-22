import "pe"

rule MAL_Compromised_Cert_FakeDocument_Verokey_75924EC04701076D5180391BB009169 {
   meta:
      description         = "Detects FakeDocument with compromised cert (Verokey)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-13"
      version             = "1.0"

      hash                = "9641288403abfd42853ee3a9d22900604e3e84810b53313bf1dda35bb2444b62"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "温江区明宇网络技术服务工作室"
      cert_issuer_short   = "Verokey"
      cert_issuer         = "Verokey Secure Code"
      cert_serial         = "75:92:4e:c0:47:01:07:6d:51:80:39:1b:b0:09:16:9"
      cert_thumbprint     = "97e0a5c80c54513714521a372d2c985927795bf5"
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
         sig.serial == "75:92:4e:c0:47:01:07:6d:51:80:39:1b:b0:09:16:9"
      )
}
