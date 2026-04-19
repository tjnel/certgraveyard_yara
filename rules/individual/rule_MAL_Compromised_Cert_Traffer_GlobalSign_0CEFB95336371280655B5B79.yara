import "pe"

rule MAL_Compromised_Cert_Traffer_GlobalSign_0CEFB95336371280655B5B79 {
   meta:
      description         = "Detects Traffer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-09"
      version             = "1.0"

      hash                = "898ea5a90810f892eecec1df9907e9a15e1dc558e74887e194fcf9553ac7a9ec"
      malware             = "Traffer"
      malware_type        = "Infostealer"
      malware_notes       = "Fake Microsoft Teams installer. Uses captcha for anti-analysis"

      signer              = "厦门云上择信信息科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0c:ef:b9:53:36:37:12:80:65:5b:5b:79"
      cert_thumbprint     = "CBE76C5D58C87F5633FBD2C4FB7A016F9E2C8A9C"
      cert_valid_from     = "2026-04-09"
      cert_valid_to       = "2027-04-10"

      country             = "CN"
      state               = "福建"
      locality            = "厦门"
      email               = "???"
      rdn_serial_number   = "91350203MA31K7A726"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0c:ef:b9:53:36:37:12:80:65:5b:5b:79"
      )
}
