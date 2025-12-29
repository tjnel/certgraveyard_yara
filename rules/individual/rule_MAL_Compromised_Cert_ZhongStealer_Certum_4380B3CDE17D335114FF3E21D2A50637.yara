import "pe"

rule MAL_Compromised_Cert_ZhongStealer_Certum_4380B3CDE17D335114FF3E21D2A50637 {
   meta:
      description         = "Detects ZhongStealer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-04"
      version             = "1.0"

      hash                = "a1a114fd875bd6f96d2ceeac2b98596c0ac56d727e4bb970becb2466cec40086"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is distributed disguised as screenshots or photos. The malware downloads secondary stages from legitimate CDN."

      signer              = "Taiyuan Feizhe Trading Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "43:80:b3:cd:e1:7d:33:51:14:ff:3e:21:d2:a5:06:37"
      cert_thumbprint     = "7ABB2B0F49378F5D53FAF8F804D0B26C1DE9D2B0"
      cert_valid_from     = "2025-12-04"
      cert_valid_to       = "2026-12-04"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "91140105MADCLAGY31"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "43:80:b3:cd:e1:7d:33:51:14:ff:3e:21:d2:a5:06:37"
      )
}
