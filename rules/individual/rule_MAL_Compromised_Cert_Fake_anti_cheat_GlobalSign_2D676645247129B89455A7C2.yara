import "pe"

rule MAL_Compromised_Cert_Fake_anti_cheat_GlobalSign_2D676645247129B89455A7C2 {
   meta:
      description         = "Detects Fake anti-cheat with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-13"
      version             = "1.0"

      hash                = "9c9fd1ab06198b6d0aa3222006a7f97e2cb29c5ea3ab1d5f408784c008a32515"
      malware             = "Fake anti-cheat"
      malware_type        = "Backdoor"
      malware_notes       = "The capability of the backdoor was described here: https://www.bilibili.com/opus/1217047827404816392"

      signer              = "湖南江玩科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2d:67:66:45:24:71:29:b8:94:55:a7:c2"
      cert_thumbprint     = "7AD9CF2C0AC0C6B5753DEA9D566C4D8D54F8DA00"
      cert_valid_from     = "2025-02-13"
      cert_valid_to       = "2026-02-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2d:67:66:45:24:71:29:b8:94:55:a7:c2"
      )
}
