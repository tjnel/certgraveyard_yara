import "pe"

rule MAL_Compromised_Cert_BatLoader_SSL_com_0AD3EC95833032EEBF53B660984CC67D {
   meta:
      description         = "Detects BatLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-03"
      version             = "1.0"

      hash                = "413cd9af982a04a8eff61e66860582f3236b2f8523b88b9330eccdd5ffc58348"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "Initial access tool dropped by ClearFake: https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/"

      signer              = "STECH CONSULTANCY LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "0a:d3:ec:95:83:30:32:ee:bf:53:b6:60:98:4c:c6:7d"
      cert_thumbprint     = "549DEBD6819A099B1EDECF964F9704088422F2BA"
      cert_valid_from     = "2023-04-03"
      cert_valid_to       = "2024-04-01"

      country             = "GB"
      state               = "???"
      locality            = "Poringland"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "0a:d3:ec:95:83:30:32:ee:bf:53:b6:60:98:4c:c6:7d"
      )
}
