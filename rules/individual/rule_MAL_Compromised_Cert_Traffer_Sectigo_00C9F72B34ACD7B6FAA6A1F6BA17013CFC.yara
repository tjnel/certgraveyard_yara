import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_00C9F72B34ACD7B6FAA6A1F6BA17013CFC {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-06"
      version             = "1.0"

      hash                = "714ffc4698d8933240c43a1cf995038f32a29d6cd55b76a4c34710c264248bc0"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Yichen Information Technology Co., Ltd"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:c9:f7:2b:34:ac:d7:b6:fa:a6:a1:f6:ba:17:01:3c:fc"
      cert_thumbprint     = "6F494D5408344F028BA211CD20FDFE35A2677D6E"
      cert_valid_from     = "2026-02-06"
      cert_valid_to       = "2027-02-06"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:c9:f7:2b:34:ac:d7:b6:fa:a6:a1:f6:ba:17:01:3c:fc"
      )
}
