import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_00FE609B027105AECAB13FBDAC0DCAC73A {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-28"
      version             = "1.0"

      hash                = "35aaa4ff2a335d4cdea859fc7402cceb9c261dcd1e9b0542308b51a3033a37ed"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Renxing Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:fe:60:9b:02:71:05:ae:ca:b1:3f:bd:ac:0d:ca:c7:3a"
      cert_thumbprint     = "B0D9EB9B19A9200B68F94ABBE531F283AF6F3689"
      cert_valid_from     = "2026-01-28"
      cert_valid_to       = "2027-01-28"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350206303142401U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:fe:60:9b:02:71:05:ae:ca:b1:3f:bd:ac:0d:ca:c7:3a"
      )
}
