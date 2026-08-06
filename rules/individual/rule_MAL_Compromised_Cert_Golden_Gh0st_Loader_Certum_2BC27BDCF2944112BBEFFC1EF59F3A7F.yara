import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_2BC27BDCF2944112BBEFFC1EF59F3A7F {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-14"
      version             = "1.0"

      hash                = "5ef6019fb6ee1db1201ee479a68669b47eb0d5d82770dbd30b05f46ccbc68f4f"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Dongguan Jieshan Technology Co., Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "2b:c2:7b:dc:f2:94:41:12:bb:ef:fc:1e:f5:9f:3a:7f"
      cert_thumbprint     = "c29c3c494a348ea879abff50dd56b85e9cb6366a"
      cert_valid_from     = "2026-07-14"
      cert_valid_to       = "2027-07-14"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Dongguan"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "2b:c2:7b:dc:f2:94:41:12:bb:ef:fc:1e:f5:9f:3a:7f"
      )
}
