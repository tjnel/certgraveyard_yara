import "pe"

rule MAL_Compromised_Cert_FakeDocusign_Sectigo_009CEFB645497C453AECC4B9F8BC5A0710 {
   meta:
      description         = "Detects FakeDocusign with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-12"
      version             = "1.0"

      hash                = "3a7f8b2c1d11f024c24c14ced04c0d4ba64b40eda0f890b393e4a06263fd019a"
      malware             = "FakeDocusign"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers delivered from websites impersonating DocuSign. Likely traffer operations targeting cryptocurrencies users worldwide"

      signer              = "Guangzhou Shuo Stone Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:9c:ef:b6:45:49:7c:45:3a:ec:c4:b9:f8:bc:5a:07:10"
      cert_thumbprint     = "4C973998DDD6BE8B255AE7A2203A8D244CAE27C3"
      cert_valid_from     = "2025-11-12"
      cert_valid_to       = "2026-11-12"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91440117MAD995LX5C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:9c:ef:b6:45:49:7c:45:3a:ec:c4:b9:f8:bc:5a:07:10"
      )
}
