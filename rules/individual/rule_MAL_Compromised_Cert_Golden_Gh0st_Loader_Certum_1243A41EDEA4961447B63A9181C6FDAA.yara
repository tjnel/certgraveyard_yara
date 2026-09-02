import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_1243A41EDEA4961447B63A9181C6FDAA {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-04"
      version             = "1.0"

      hash                = "9a60b23dea48bf8ae6db72a845788c7c714c2ac82ba5a6e5a3e4c2833e198d8f"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Chongqing Meinuoxi Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "12:43:a4:1e:de:a4:96:14:47:b6:3a:91:81:c6:fd:aa"
      cert_thumbprint     = "7e220cb13e0bd7caf755b54d8e85625cb98bb527"
      cert_valid_from     = "2026-08-04"
      cert_valid_to       = "2027-08-04"

      country             = "CN"
      state               = "Chongqing"
      locality            = "Chongqing"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "12:43:a4:1e:de:a4:96:14:47:b6:3a:91:81:c6:fd:aa"
      )
}
