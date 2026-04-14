import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_0AF316CB4E5D9BAF35B35E85677B17EE {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-11"
      version             = "1.0"

      hash                = "f76c31ecdafb59279833f17f350d9c2b1317da269823097e8dd1736c72449c88"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PALIT MICROSYSTEMS LTD. TAIWAN BRANCH (BELIZE)"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0a:f3:16:cb:4e:5d:9b:af:35:b3:5e:85:67:7b:17:ee"
      cert_thumbprint     = "FBA16B68994972218252024AA5623A784E32D7AA"
      cert_valid_from     = "2026-04-11"
      cert_valid_to       = "2027-04-10"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0a:f3:16:cb:4e:5d:9b:af:35:b3:5e:85:67:7b:17:ee"
      )
}
