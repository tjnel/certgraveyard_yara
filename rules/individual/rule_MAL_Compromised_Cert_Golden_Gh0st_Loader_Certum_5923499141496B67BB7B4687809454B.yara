import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_5923499141496B67BB7B4687809454B {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-13"
      version             = "1.0"

      hash                = "21498faad7283839d0b055c618693eb2affe910b6e8d030592d92a94cd266144"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Hangzhou Yueque Li Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "59:23:49:91:41:49:6b:67:bb:7b:46:87:80:94:54:b"
      cert_thumbprint     = "950cee0cf90d33f1264430fb59dd391ee37b3698"
      cert_valid_from     = "2026-08-13"
      cert_valid_to       = "2027-08-13"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "59:23:49:91:41:49:6b:67:bb:7b:46:87:80:94:54:b"
      )
}
