import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Verokey_BCDF5E0DA32D68900B8B7638459D072 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Verokey)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-13"
      version             = "1.0"

      hash                = "7270d05e8d42a82634ee2ac52b7256557612b22e7e60fc56a05cb5961a9c2f02"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "温江区明宇网络技术服务工作室"
      cert_issuer_short   = "Verokey"
      cert_issuer         = "Verokey Secure Code"
      cert_serial         = "bc:df:5e:0d:a3:2d:68:90:0b:8b:76:38:45:9d:07:2"
      cert_thumbprint     = "18ddaa9c417e4536728d648b9df47a05426d94fc"
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
         sig.serial == "bc:df:5e:0d:a3:2d:68:90:0b:8b:76:38:45:9d:07:2"
      )
}
