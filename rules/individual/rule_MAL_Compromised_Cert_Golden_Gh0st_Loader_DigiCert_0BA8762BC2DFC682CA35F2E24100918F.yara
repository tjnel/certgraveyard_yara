import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_DigiCert_0BA8762BC2DFC682CA35F2E24100918F {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-05"
      version             = "1.0"

      hash                = "25787f5541566d193f35b220b4953a6057aabc05a54bf9b7cf903fb8fdf26912"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tencent Technology (Shenzhen) Company Limited"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0b:a8:76:2b:c2:df:c6:82:ca:35:f2:e2:41:00:91:8f"
      cert_thumbprint     = "67de1a4fb2174930244b306b14e2d7bf67cd05f0"
      cert_valid_from     = "2026-04-05"
      cert_valid_to       = "2027-04-04"

      country             = "CN"
      state               = "Guangdong Province"
      locality            = "Shenzhen"
      email               = "---"
      rdn_serial_number   = "9144030071526726XG"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0b:a8:76:2b:c2:df:c6:82:ca:35:f2:e2:41:00:91:8f"
      )
}
