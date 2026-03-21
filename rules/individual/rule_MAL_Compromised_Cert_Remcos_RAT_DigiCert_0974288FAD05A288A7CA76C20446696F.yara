import "pe"

rule MAL_Compromised_Cert_Remcos_RAT_DigiCert_0974288FAD05A288A7CA76C20446696F {
   meta:
      description         = "Detects Remcos RAT with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-13"
      version             = "1.0"

      hash                = "3a9dd3d0e2ef10f78b5a2685ef7005a2ae8be55373dae46e5bd23fad7591aee5"
      malware             = "Remcos RAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "JUST OKAY LIMITED"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "09:74:28:8f:ad:05:a2:88:a7:ca:76:c2:04:46:69:6f"
      cert_thumbprint     = "CB889AD259D7B829547479857BED8BD359902817"
      cert_valid_from     = "2025-11-13"
      cert_valid_to       = "2026-12-18"

      country             = "HK"
      state               = "???"
      locality            = "Kowloon"
      email               = "???"
      rdn_serial_number   = "72759881"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "09:74:28:8f:ad:05:a2:88:a7:ca:76:c2:04:46:69:6f"
      )
}
