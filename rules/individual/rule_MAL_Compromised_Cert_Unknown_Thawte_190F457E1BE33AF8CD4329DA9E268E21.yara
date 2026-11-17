import "pe"

rule MAL_Compromised_Cert_Unknown_Thawte_190F457E1BE33AF8CD4329DA9E268E21 {
   meta:
      description         = "Detects Unknown with compromised cert (Thawte)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2014-12-11"
      version             = "1.0"

      hash                = "dda67a294e6a086022e1ba51f2ff9a63addf16dc865d9205741caa9a35df0d33"
      malware             = "Unknown"
      malware_type        = "Backdoor"
      malware_notes       = "Kernel resident backdoor: https://rogueauthority.org/windows-kernel-backdoor-no-user-mode-half"

      signer              = "Beijing Datang Shenzhou Technology Co., Ltd."
      cert_issuer_short   = "Thawte"
      cert_issuer         = "Thawte Code Signing CA - G2"
      cert_serial         = "19:0f:45:7e:1b:e3:3a:f8:cd:43:29:da:9e:26:8e:21"
      cert_thumbprint     = "d5dfc60a63446f52def563d318b7535e4f390bb0"
      cert_valid_from     = "2014-12-11"
      cert_valid_to       = "2016-12-10"

      country             = "CN"
      state               = "北京"
      locality            = "北京"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Thawte Code Signing CA - G2" and
         sig.serial == "19:0f:45:7e:1b:e3:3a:f8:cd:43:29:da:9e:26:8e:21"
      )
}
