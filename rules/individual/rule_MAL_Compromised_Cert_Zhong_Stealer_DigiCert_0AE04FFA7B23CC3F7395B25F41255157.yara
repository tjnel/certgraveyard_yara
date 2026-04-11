import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_0AE04FFA7B23CC3F7395B25F41255157 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-04"
      version             = "1.0"

      hash                = "c08a59750b5a72761d457e7b9875aa251f71c64d0c6bf7e391bb5c5f35cefc3c"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "Luxvisions Innovation Technology Corp. Limited"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0a:e0:4f:fa:7b:23:cc:3f:73:95:b2:5f:41:25:51:57"
      cert_thumbprint     = "D569373B0DE55B737BAFB92656E5E3FFD1C47FEE"
      cert_valid_from     = "2026-04-04"
      cert_valid_to       = "2027-04-03"

      country             = "CN"
      state               = "Guangdong Province"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440101MA5AQWN78F"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0a:e0:4f:fa:7b:23:cc:3f:73:95:b2:5f:41:25:51:57"
      )
}
