import "pe"

rule MAL_Compromised_Cert_SmokedHam_Sectigo_00B0D4CE585BFBD203E9C4056C5583C3B4 {
   meta:
      description         = "Detects SmokedHam with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-27"
      version             = "1.0"

      hash                = "863074914d88d72874e616de171bfababc9c11bc53bf39216b3db52ab02c11b4"
      malware             = "SmokedHam"
      malware_type        = "Unknown"
      malware_notes       = "Fake RVTools"

      signer              = "Xiamen Fangjin Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b0:d4:ce:58:5b:fb:d2:03:e9:c4:05:6c:55:83:c3:b4"
      cert_thumbprint     = "32BEFB1C0459DE0DB9E013D1BC98334004F69913"
      cert_valid_from     = "2026-02-27"
      cert_valid_to       = "2027-02-27"

      country             = "CN"
      state               = "福建省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350206MA2YLB1U8Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b0:d4:ce:58:5b:fb:d2:03:e9:c4:05:6c:55:83:c3:b4"
      )
}
