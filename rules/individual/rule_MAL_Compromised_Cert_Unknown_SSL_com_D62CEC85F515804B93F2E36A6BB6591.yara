import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_D62CEC85F515804B93F2E36A6BB6591 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-03"
      version             = "1.0"

      hash                = "0c3fecbafbce9a394f539243edaf39c6e73e60c46147aafd4d1007f0776618a8"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "X G.K."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "d6:2c:ec:85:f5:15:80:4b:93:f2:e3:6a:6b:b6:59:1"
      cert_thumbprint     = "94b67d19b3c28610bdddd61746d91bc371a3bf21"
      cert_valid_from     = "2026-06-03"
      cert_valid_to       = "2027-06-03"

      country             = "JP"
      state               = "Tokyo"
      locality            = "Minato-ku"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "d6:2c:ec:85:f5:15:80:4b:93:f2:e3:6a:6b:b6:59:1"
      )
}
