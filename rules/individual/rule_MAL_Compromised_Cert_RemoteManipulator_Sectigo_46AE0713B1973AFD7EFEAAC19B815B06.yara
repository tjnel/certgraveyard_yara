import "pe"

rule MAL_Compromised_Cert_RemoteManipulator_Sectigo_46AE0713B1973AFD7EFEAAC19B815B06 {
   meta:
      description         = "Detects RemoteManipulator with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-02"
      version             = "1.0"

      hash                = "acae87a39faff99d12c7bd853c2f7cd74380f253a5c87770b9f7e13a4bd6a425"
      malware             = "RemoteManipulator"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hefei Xuxuan New Energy Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "46:ae:07:13:b1:97:3a:fd:7e:fe:aa:c1:9b:81:5b:06"
      cert_thumbprint     = "1906BB377C48CE7CE094952AF13CADECF3FC1230"
      cert_valid_from     = "2026-02-02"
      cert_valid_to       = "2027-02-02"

      country             = "CN"
      state               = "Anhui Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91340100MA2W494F4P"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "46:ae:07:13:b1:97:3a:fd:7e:fe:aa:c1:9b:81:5b:06"
      )
}
