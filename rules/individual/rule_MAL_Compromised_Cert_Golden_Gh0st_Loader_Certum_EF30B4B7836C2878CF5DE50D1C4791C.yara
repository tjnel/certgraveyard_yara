import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_EF30B4B7836C2878CF5DE50D1C4791C {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-28"
      version             = "1.0"

      hash                = "91dfe3049b9de072378178064f2a248efa13dcdc23e0b51e578a5f4378e2b827"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Meisi Software Development (Guangxi) Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "ef:30:b4:b7:83:6c:28:78:cf:5d:e5:0d:1c:47:91:c"
      cert_thumbprint     = "d5c3b2e0c181f27bbcf830f83e0248dcb81a823c"
      cert_valid_from     = "2026-07-28"
      cert_valid_to       = "2027-07-28"

      country             = "CN"
      state               = "广西壮族自治区"
      locality            = "玉林市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "ef:30:b4:b7:83:6c:28:78:cf:5d:e5:0d:1c:47:91:c"
      )
}
