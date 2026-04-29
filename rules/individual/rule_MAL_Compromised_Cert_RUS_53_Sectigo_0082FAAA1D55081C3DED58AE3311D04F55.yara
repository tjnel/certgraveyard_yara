import "pe"

rule MAL_Compromised_Cert_RUS_53_Sectigo_0082FAAA1D55081C3DED58AE3311D04F55 {
   meta:
      description         = "Detects RUS-53 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-04"
      version             = "1.0"

      hash                = "b55744aae0b02269036f9c4d21a363fdc82409bbd3c462c8b2bc179574f64bbc"
      malware             = "RUS-53"
      malware_type        = "Loader"
      malware_notes       = "Disguised as PDF load txt decoy."

      signer              = "Xiamen Chike Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:82:fa:aa:1d:55:08:1c:3d:ed:58:ae:33:11:d0:4f:55"
      cert_thumbprint     = "C6ED7CEC3B00501F292A15A2130336084A1D044D"
      cert_valid_from     = "2026-02-04"
      cert_valid_to       = "2027-02-04"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350206302884593A"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:82:fa:aa:1d:55:08:1c:3d:ed:58:ae:33:11:d0:4f:55"
      )
}
