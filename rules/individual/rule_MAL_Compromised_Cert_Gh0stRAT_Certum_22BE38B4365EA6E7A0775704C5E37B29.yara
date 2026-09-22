import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_Certum_22BE38B4365EA6E7A0775704C5E37B29 {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-12"
      version             = "1.0"

      hash                = "cd74c3950fb8efc4d6571a2be00a68c22886fecca49887c638d7886c20ea73dc"
      malware             = "Gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = "C2: 103.145.191.136"

      signer              = "泉州登尚文化传播有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "22:be:38:b4:36:5e:a6:e7:a0:77:57:04:c5:e3:7b:29"
      cert_thumbprint     = "4a58f4702de3274cccb9e34d5d5fe88921f6a744"
      cert_valid_from     = "2026-06-12"
      cert_valid_to       = "2027-06-12"

      country             = "CN"
      state               = "福建省"
      locality            = "石狮市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "22:be:38:b4:36:5e:a6:e7:a0:77:57:04:c5:e3:7b:29"
      )
}
