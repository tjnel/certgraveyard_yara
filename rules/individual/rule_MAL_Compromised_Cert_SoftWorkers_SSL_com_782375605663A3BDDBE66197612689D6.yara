import "pe"

rule MAL_Compromised_Cert_SoftWorkers_SSL_com_782375605663A3BDDBE66197612689D6 {
   meta:
      description         = "Detects SoftWorkers with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-23"
      version             = "1.0"

      hash                = "db6726180b2fc1f64cd7bd6accfb91b7958aca37b3fade08fea25882544a392f"
      malware             = "SoftWorkers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sierra Brumfield"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "78:23:75:60:56:63:a3:bd:db:e6:61:97:61:26:89:d6"
      cert_thumbprint     = "b2acedede4871af791d226b5549e18d63879ca2e"
      cert_valid_from     = "2026-10-23"
      cert_valid_to       = "2027-10-23"

      country             = "US"
      state               = "Mississippi"
      locality            = "McComb"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "78:23:75:60:56:63:a3:bd:db:e6:61:97:61:26:89:d6"
      )
}
