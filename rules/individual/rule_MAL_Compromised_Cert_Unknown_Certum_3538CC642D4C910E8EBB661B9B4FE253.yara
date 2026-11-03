import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_3538CC642D4C910E8EBB661B9B4FE253 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "a62c87a28f32b2a2965653f587cd3cfdcc42d13a59bc365261adc7cd342235cc"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "松原市球记网络科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "35:38:cc:64:2d:4c:91:0e:8e:bb:66:1b:9b:4f:e2:53"
      cert_thumbprint     = "3d50618a104834e84d2f39fde402939558b67299"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2027-03-23"

      country             = "CN"
      state               = "吉林"
      locality            = "松原"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "35:38:cc:64:2d:4c:91:0e:8e:bb:66:1b:9b:4f:e2:53"
      )
}
