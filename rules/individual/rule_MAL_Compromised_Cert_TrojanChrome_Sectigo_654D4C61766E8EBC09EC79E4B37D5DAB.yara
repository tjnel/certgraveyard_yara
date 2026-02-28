import "pe"

rule MAL_Compromised_Cert_TrojanChrome_Sectigo_654D4C61766E8EBC09EC79E4B37D5DAB {
   meta:
      description         = "Detects TrojanChrome with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-14"
      version             = "1.0"

      hash                = "099d63e692457bfccc2cf59278ae6a268cb03964f18d0d27f536027b43c89896"
      malware             = "TrojanChrome"
      malware_type        = "Unknown"
      malware_notes       = "Fake Chrome installer bundled with drivers[.]solutions/META-INF/xuoa.sys"

      signer              = "Hubei Da'e Zhidao Food Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "65:4d:4c:61:76:6e:8e:bc:09:ec:79:e4:b3:7d:5d:ab"
      cert_thumbprint     = "732BF1DCB42EBBC8ADA9102FDD927239D2640B5E"
      cert_valid_from     = "2026-01-14"
      cert_valid_to       = "2027-01-14"

      country             = "CN"
      state               = "Hubei Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91420112MA4F1P255Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "65:4d:4c:61:76:6e:8e:bc:09:ec:79:e4:b3:7d:5d:ab"
      )
}
