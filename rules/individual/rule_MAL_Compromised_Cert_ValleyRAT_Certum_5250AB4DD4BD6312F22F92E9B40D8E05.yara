import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_5250AB4DD4BD6312F22F92E9B40D8E05 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-13"
      version             = "1.0"

      hash                = "643458abc17da13200343c39fb728ed98691f4e09583156124c19958bf04bd75"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "上饶市嘉端科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "52:50:ab:4d:d4:bd:63:12:f2:2f:92:e9:b4:0d:8e:05"
      cert_thumbprint     = "37e0ca1ffe95ddf08d4979efeb4af05668b89bef"
      cert_valid_from     = "2026-08-13"
      cert_valid_to       = "2027-08-13"

      country             = "CN"
      state               = "江西省"
      locality            = "上饶市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "52:50:ab:4d:d4:bd:63:12:f2:2f:92:e9:b4:0d:8e:05"
      )
}
