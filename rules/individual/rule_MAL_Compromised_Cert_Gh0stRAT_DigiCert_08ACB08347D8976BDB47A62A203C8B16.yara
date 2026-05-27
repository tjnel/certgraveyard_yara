import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_DigiCert_08ACB08347D8976BDB47A62A203C8B16 {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-05"
      version             = "1.0"

      hash                = "68508736c04c34fd3ed97b5d7ca86cbb4ec12e2ae118fe1854f6813aa7706cf5"
      malware             = "Gh0stRAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "北京宏芯互联网销售有限公司"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "08:ac:b0:83:47:d8:97:6b:db:47:a6:2a:20:3c:8b:16"
      cert_thumbprint     = "CE18742F500BCF3BB448568DE8E38E8211DB591E"
      cert_valid_from     = "2025-09-05"
      cert_valid_to       = "2028-12-01"

      country             = "CN"
      state               = "Beijing"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91110117MABMFHHX3C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "08:ac:b0:83:47:d8:97:6b:db:47:a6:2a:20:3c:8b:16"
      )
}
