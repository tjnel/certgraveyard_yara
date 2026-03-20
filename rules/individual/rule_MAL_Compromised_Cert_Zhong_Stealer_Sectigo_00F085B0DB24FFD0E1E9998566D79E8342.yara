import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_00F085B0DB24FFD0E1E9998566D79E8342 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-27"
      version             = "1.0"

      hash                = "f042b510f67620272140417df73d16136b2b0b15fb28145cd1f058ea40c282fc"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "Xiamen Renxing Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:f0:85:b0:db:24:ff:d0:e1:e9:99:85:66:d7:9e:83:42"
      cert_thumbprint     = "F03A8D3792D36F2572CDC3F230347F5F0C87959D"
      cert_valid_from     = "2026-01-27"
      cert_valid_to       = "2027-01-27"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:f0:85:b0:db:24:ff:d0:e1:e9:99:85:66:d7:9e:83:42"
      )
}
