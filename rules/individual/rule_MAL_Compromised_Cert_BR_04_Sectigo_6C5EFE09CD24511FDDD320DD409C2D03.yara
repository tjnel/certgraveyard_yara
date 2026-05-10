import "pe"

rule MAL_Compromised_Cert_BR_04_Sectigo_6C5EFE09CD24511FDDD320DD409C2D03 {
   meta:
      description         = "Detects BR-04 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-12"
      version             = "1.0"

      hash                = "6210caacd4c7a3219ad6327b714c53d286443104ba06e3c4270f7e9a5d25ecee"
      malware             = "BR-04"
      malware_type        = "Backdoor"
      malware_notes       = ""

      signer              = "Pingxiang De'a Zhiyun Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "6c:5e:fe:09:cd:24:51:1f:dd:d3:20:dd:40:9c:2d:03"
      cert_thumbprint     = "6CC658B759643E211DDEEC44C6EAEF52BA7CA0A2"
      cert_valid_from     = "2026-03-12"
      cert_valid_to       = "2027-03-12"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "6c:5e:fe:09:cd:24:51:1f:dd:d3:20:dd:40:9c:2d:03"
      )
}
