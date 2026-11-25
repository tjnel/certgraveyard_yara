import "pe"

rule MAL_Compromised_Cert_Cloudhaze_Sectigo_4715717AE3C2E72ED180F9D7EA2699BF {
   meta:
      description         = "Detects Cloudhaze with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "6c71fa2bc8739baabb4ae0a2ac92006b7e9757458e42a25cf3ef7f0870aaf772"
      malware             = "Cloudhaze"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Cute Industry Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "47:15:71:7a:e3:c2:e7:2e:d1:80:f9:d7:ea:26:99:bf"
      cert_thumbprint     = "96df81899492c1a8276111852db57fe4f2003ccf"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2027-03-23"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "47:15:71:7a:e3:c2:e7:2e:d1:80:f9:d7:ea:26:99:bf"
      )
}
