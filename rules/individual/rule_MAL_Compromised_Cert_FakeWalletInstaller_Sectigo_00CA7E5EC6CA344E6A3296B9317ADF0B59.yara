import "pe"

rule MAL_Compromised_Cert_FakeWalletInstaller_Sectigo_00CA7E5EC6CA344E6A3296B9317ADF0B59 {
   meta:
      description         = "Detects FakeWalletInstaller with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-16"
      version             = "1.0"

      hash                = "33249913aaff8172a459eba02c38d10ebbb7644c9b3d09c4bcc5ccd1a1e4bfa1"
      malware             = "FakeWalletInstaller"
      malware_type        = "Infostealer"
      malware_notes       = "The application was disguised to be a Neon Wallet installer."

      signer              = "Jiangyin Kenadi International Trade Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ca:7e:5e:c6:ca:34:4e:6a:32:96:b9:31:7a:df:0b:59"
      cert_thumbprint     = "5AF0EADE73CDA1DFF0F2F4C5B644D5D43598B7E3"
      cert_valid_from     = "2025-12-16"
      cert_valid_to       = "2026-12-16"

      country             = "CN"
      state               = "Jiangsu Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91320281MA1XEGJA1C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ca:7e:5e:c6:ca:34:4e:6a:32:96:b9:31:7a:df:0b:59"
      )
}
