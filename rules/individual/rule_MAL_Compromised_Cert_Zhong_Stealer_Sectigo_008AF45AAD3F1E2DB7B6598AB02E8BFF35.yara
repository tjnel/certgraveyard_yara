import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_008AF45AAD3F1E2DB7B6598AB02E8BFF35 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "e5a0289fa38bbbf958ebc57cee082111b55f7b8aa20aa9f2e52a38fd66011e80"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Baoding Software Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:8a:f4:5a:ad:3f:1e:2d:b7:b6:59:8a:b0:2e:8b:ff:35"
      cert_thumbprint     = "4A118F3C82A19201C0C017F632D43FBC8D5E89CA"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2027-03-23"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350200MA349M0219"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:8a:f4:5a:ad:3f:1e:2d:b7:b6:59:8a:b0:2e:8b:ff:35"
      )
}
