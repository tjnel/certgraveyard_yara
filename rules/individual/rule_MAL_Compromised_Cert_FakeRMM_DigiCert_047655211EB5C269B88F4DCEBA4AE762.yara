import "pe"

rule MAL_Compromised_Cert_FakeRMM_DigiCert_047655211EB5C269B88F4DCEBA4AE762 {
   meta:
      description         = "Detects FakeRMM with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-16"
      version             = "1.0"

      hash                = "dee3b88825ea12734b4d537c15d7d2d177e9f869e7d6ea43642e316c9f4f9970"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers posing as a fake RMM tool. Ref: https://www.proofpoint.com/us/blog/threat-insight/dont-trustconnect-its-a-rat"

      signer              = "TRUSTCONNECT SOFTWARE"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "04:76:55:21:1e:b5:c2:69:b8:8f:4d:ce:ba:4a:e7:62"
      cert_thumbprint     = "7878684A34FDD35B1002EF96379A3133BA8BC19B"
      cert_valid_from     = "2026-02-16"
      cert_valid_to       = "2027-02-16"

      country             = "ZA"
      state               = "Gauteng"
      locality            = "Johannesburg"
      email               = "???"
      rdn_serial_number   = "K2026029661"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "04:76:55:21:1e:b5:c2:69:b8:8f:4d:ce:ba:4a:e7:62"
      )
}
