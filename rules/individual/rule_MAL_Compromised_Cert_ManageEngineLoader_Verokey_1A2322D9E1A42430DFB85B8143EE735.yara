import "pe"

rule MAL_Compromised_Cert_ManageEngineLoader_Verokey_1A2322D9E1A42430DFB85B8143EE735 {
   meta:
      description         = "Detects ManageEngineLoader with compromised cert (Verokey)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-13"
      version             = "1.0"

      hash                = "2f92aa2df9cd99c432bcc12481177682d843b99ee07ef98b50b978ebbc6e5df8"
      malware             = "ManageEngineLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "温江区明宇网络技术服务工作室"
      cert_issuer_short   = "Verokey"
      cert_issuer         = "Verokey Secure Code"
      cert_serial         = "1a:23:22:d9:e1:a4:24:30:df:b8:5b:81:43:ee:73:5"
      cert_thumbprint     = "b54ff8566e8d816561f7c96a15395e2de91de83b"
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
         sig.serial == "1a:23:22:d9:e1:a4:24:30:df:b8:5b:81:43:ee:73:5"
      )
}
