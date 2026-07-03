import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_Certum_2D85A7A16D1EB86DFD92B00F6267733D {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-07"
      version             = "1.0"

      hash                = "5bc484cc3decc236000d86e18adac779bb5e5690ec226f6823af3cc91b0a2284"
      malware             = "Gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = "C2: gogousdtdiaoyu.org"

      signer              = "沂水县极客网络科技服务工作室（个体工商户）"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "2d:85:a7:a1:6d:1e:b8:6d:fd:92:b0:0f:62:67:73:3d"
      cert_thumbprint     = "A37552D67943E0E6C559DAF8BC2FA938B988C773"
      cert_valid_from     = "2026-05-07"
      cert_valid_to       = "2027-05-07"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "2d:85:a7:a1:6d:1e:b8:6d:fd:92:b0:0f:62:67:73:3d"
      )
}
