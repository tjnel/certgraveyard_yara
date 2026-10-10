import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_1B56CB4E99FB9444645A1CE7FFC0A46B {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guangzhou Guoying Communication Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "1b:56:cb:4e:99:fb:94:44:64:5a:1c:e7:ff:c0:a4:6b"
      cert_thumbprint     = "61DBDAD36F650A8F47C5068578F7EC9ED3A222FB"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-04-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "1b:56:cb:4e:99:fb:94:44:64:5a:1c:e7:ff:c0:a4:6b"
      )
}
