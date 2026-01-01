import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_00E3CFD617A941C74853AC65890BB6C46A {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-11"
      version             = "1.0"

      hash                = "4cf973d3c8985c32572680203bc01121cf18342f75c139ec0fb202900809917c"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "The malware file is named similar to a screenshot or image, pulls second stage contents off of legitimate CDN."

      signer              = "RichQuest Network Technology Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:e3:cf:d6:17:a9:41:c7:48:53:ac:65:89:0b:b6:c4:6a"
      cert_thumbprint     = "0C4CF82C6D22B8A57A2EC4B475A4C8E9D0BBA092"
      cert_valid_from     = "2025-08-11"
      cert_valid_to       = "2026-08-11"

      country             = "CN"
      state               = "Jilin Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91220702MABPBBD61L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:e3:cf:d6:17:a9:41:c7:48:53:ac:65:89:0b:b6:c4:6a"
      )
}
