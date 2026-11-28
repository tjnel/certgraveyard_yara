import "pe"

rule MAL_Compromised_Cert_WailsLoader_likely_SSL_com_6F9FBC96C2EFA75EBFDC5356E1E926F0 {
   meta:
      description         = "Detects WailsLoader (likely) with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-28"
      version             = "1.0"

      hash                = "afbaf406b040396f1ce58dc749b06dc1a4e40584a38b9ac2a97da9c43555fc7c"
      malware             = "WailsLoader (likely)"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Rosario Ayelen Espinosa"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "6f:9f:bc:96:c2:ef:a7:5e:bf:dc:53:56:e1:e9:26:f0"
      cert_thumbprint     = "1F53EFBBD1B65E98BAAF24301070B927FEE2A933"
      cert_valid_from     = "2026-09-28"
      cert_valid_to       = "2027-09-28"

      country             = "AR"
      state               = "Santa Fe"
      locality            = "Recreo"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "6f:9f:bc:96:c2:ef:a7:5e:bf:dc:53:56:e1:e9:26:f0"
      )
}
