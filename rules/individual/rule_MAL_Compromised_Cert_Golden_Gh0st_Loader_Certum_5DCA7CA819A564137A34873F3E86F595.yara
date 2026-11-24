import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_5DCA7CA819A564137A34873F3E86F595 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-23"
      version             = "1.0"

      hash                = "3f447a57f2545fa98a222e86046438eb590678189d79f98bc96b67dc892ce9cb"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hangzhou Chuang Wen Speed Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5d:ca:7c:a8:19:a5:64:13:7a:34:87:3f:3e:86:f5:95"
      cert_thumbprint     = "e29373841f4ca0358770d74d333d232299e5ab85"
      cert_valid_from     = "2026-08-23"
      cert_valid_to       = "2027-08-23"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5d:ca:7c:a8:19:a5:64:13:7a:34:87:3f:3e:86:f5:95"
      )
}
