import "pe"

rule MAL_Compromised_Cert_BumbleBee_Sectigo_67BEA002D62E1831CC2612ADB8E1B2CE {
   meta:
      description         = "Detects BumbleBee with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-23"
      version             = "1.0"

      hash                = "640c518ff312e024c1e3bb198a2240c59b2205ab562053a1e644276592a5c07d"
      malware             = "BumbleBee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Xisu Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "67:be:a0:02:d6:2e:18:31:cc:26:12:ad:b8:e1:b2:ce"
      cert_thumbprint     = "BAF6F7831218C352B4CB784EB54A6E86319138AC"
      cert_valid_from     = "2026-01-23"
      cert_valid_to       = "2027-01-23"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350200MA35CYLRX4"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "67:be:a0:02:d6:2e:18:31:cc:26:12:ad:b8:e1:b2:ce"
      )
}
