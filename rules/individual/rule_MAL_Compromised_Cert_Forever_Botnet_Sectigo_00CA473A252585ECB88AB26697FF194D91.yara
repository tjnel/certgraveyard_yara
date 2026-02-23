import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_Sectigo_00CA473A252585ECB88AB26697FF194D91 {
   meta:
      description         = "Detects Forever Botnet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-27"
      version             = "1.0"

      hash                = "473a013ae706915b43a046239821356afe4572c15e621f4ee63883e766c63af6"
      malware             = "Forever Botnet"
      malware_type        = "Unknown"
      malware_notes       = "Malware campaign targeting BR users via fake documents. C2: cms[.]lmcnow[.]com/q/"

      signer              = "Xiamen Time Travel Network Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ca:47:3a:25:25:85:ec:b8:8a:b2:66:97:ff:19:4d:91"
      cert_thumbprint     = "58FC7F333D1D7E65B75D9FC97B7FC4C1E67D17F7"
      cert_valid_from     = "2026-01-27"
      cert_valid_to       = "2027-01-27"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350203769285658W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ca:47:3a:25:25:85:ec:b8:8a:b2:66:97:ff:19:4d:91"
      )
}
