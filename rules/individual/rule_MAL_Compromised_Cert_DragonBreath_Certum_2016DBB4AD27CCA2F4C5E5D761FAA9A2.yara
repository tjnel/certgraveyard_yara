import "pe"

rule MAL_Compromised_Cert_DragonBreath_Certum_2016DBB4AD27CCA2F4C5E5D761FAA9A2 {
   meta:
      description         = "Detects DragonBreath with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-04"
      version             = "1.0"

      hash                = "03f41826ee5624e938ff9de7b621fc954decdf4b6f8cc266c43706881053c1ba"
      malware             = "DragonBreath"
      malware_type        = "Unknown"
      malware_notes       = "APT DragonBreath campaign spotted targeting Cambodia. Ref: https://x.com/PrakkiSathwik/status/2013512888875655436"

      signer              = "Yongji Zaihui E-commerce Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "20:16:db:b4:ad:27:cc:a2:f4:c5:e5:d7:61:fa:a9:a2"
      cert_thumbprint     = "EAE3B98E04DE4721E730D85C1360706DB763FEB4"
      cert_valid_from     = "2025-12-04"
      cert_valid_to       = "2026-12-04"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Yongji"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "20:16:db:b4:ad:27:cc:a2:f4:c5:e5:d7:61:fa:a9:a2"
      )
}
