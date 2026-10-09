import "pe"

rule MAL_Compromised_Cert_FakeRVTools_GlobalSign_152BE2DC6D8F554095868AB6 {
   meta:
      description         = "Detects FakeRVTools with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-29"
      version             = "1.0"

      hash                = "27e1594334eabcf7d927fb444dabc1f4221a36a8faf13b741ac65a9b1a23c87b"
      malware             = "FakeRVTools"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Allsoft Systems OÜ"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "15:2b:e2:dc:6d:8f:55:40:95:86:8a:b6"
      cert_thumbprint     = "d863686040411c1a54ae488c6dcf5ddd6c75824d"
      cert_valid_from     = "2026-06-29"
      cert_valid_to       = "2027-06-30"

      country             = "EE"
      state               = "Harjumaa"
      locality            = "Tallin"
      email               = "info@allsoftsystems.com"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "15:2b:e2:dc:6d:8f:55:40:95:86:8a:b6"
      )
}
