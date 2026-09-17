import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_62F7C75FF5903A746F370DE8F943CE11 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-12"
      version             = "1.0"

      hash                = "036f32eb1efeda24d24aed500992461301a8fab1d672833ef15f85b7b6171d11"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xi 'an Yuerui Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "62:f7:c7:5f:f5:90:3a:74:6f:37:0d:e8:f9:43:ce:11"
      cert_thumbprint     = "6127732aefc01ab6c33c8b36416b5f60169ebe8f"
      cert_valid_from     = "2026-08-12"
      cert_valid_to       = "2027-08-12"

      country             = "CN"
      state               = "陕西省"
      locality            = "西安市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "62:f7:c7:5f:f5:90:3a:74:6f:37:0d:e8:f9:43:ce:11"
      )
}
