import "pe"

rule MAL_Compromised_Cert_TransferLoader_Sectigo_7A37178F179E98A61707912AD0DEB4F9 {
   meta:
      description         = "Detects TransferLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-04"
      version             = "1.0"

      hash                = "9d8373d9bccb3ba200e4c1aae48c083736298c4eb3a37feb17896bcf5cb02616"
      malware             = "TransferLoader"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "Xiamen Zhiqing Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "7a:37:17:8f:17:9e:98:a6:17:07:91:2a:d0:de:b4:f9"
      cert_thumbprint     = "92970EDFC9E778A9CF21918ED38D6483233C6963"
      cert_valid_from     = "2026-03-04"
      cert_valid_to       = "2027-03-04"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350205MACM7UFB4Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "7a:37:17:8f:17:9e:98:a6:17:07:91:2a:d0:de:b4:f9"
      )
}
