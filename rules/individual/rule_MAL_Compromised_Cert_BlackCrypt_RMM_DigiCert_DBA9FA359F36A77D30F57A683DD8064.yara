import "pe"

rule MAL_Compromised_Cert_BlackCrypt_RMM_DigiCert_DBA9FA359F36A77D30F57A683DD8064 {
   meta:
      description         = "Detects BlackCrypt RMM with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-26"
      version             = "1.0"

      hash                = "bb5c49eaa94615f7d75cfa80afb8e79b12da2defc47d9b9c53d7602e7171b668"
      malware             = "BlackCrypt RMM"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "C&P Global Investors LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "db:a9:fa:35:9f:36:a7:7d:30:f5:7a:68:3d:d8:06:4"
      cert_thumbprint     = "17ac77612f471dcddb47b4d1169c2f4e746f7833"
      cert_valid_from     = "2026-04-26"
      cert_valid_to       = "2027-04-27"

      country             = "US"
      state               = "California"
      locality            = "Fresno"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "db:a9:fa:35:9f:36:a7:7d:30:f5:7a:68:3d:d8:06:4"
      )
}
