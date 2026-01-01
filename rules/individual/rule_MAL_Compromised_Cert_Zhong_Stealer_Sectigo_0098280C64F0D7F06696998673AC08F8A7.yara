import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_0098280C64F0D7F06696998673AC08F8A7 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-17"
      version             = "1.0"

      hash                = "cb7793147566cb0cbd2d60918e4825389c549d8a9b89cec611c12ecb028593f5"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This is a malware we track as Zhong Stealer; it is frequently delivered disguised as a image or a screenshot; it then pulls its second stage off of legitimate CDN."

      signer              = "Jieyang Santian E-commerce Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:98:28:0c:64:f0:d7:f0:66:96:99:86:73:ac:08:f8:a7"
      cert_thumbprint     = "769CE5E5558DA6C60F6829E66A1F5DB12151C636"
      cert_valid_from     = "2025-12-17"
      cert_valid_to       = "2026-12-17"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91445221MAD886Y555"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:98:28:0c:64:f0:d7:f0:66:96:99:86:73:ac:08:f8:a7"
      )
}
