import "pe"

rule MAL_Compromised_Cert_MiniFast_SSL_com_20F3685DB7E46221F636A23E51E23A64 {
   meta:
      description         = "Detects MiniFast with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-21"
      version             = "1.0"

      hash                = "d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2"
      malware             = "MiniFast"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Gray Matter Software S.R.L."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "20:f3:68:5d:b7:e4:62:21:f6:36:a2:3e:51:e2:3a:64"
      cert_thumbprint     = "26542462CE31BE0FE2905967562C733DCC0BE667"
      cert_valid_from     = "2025-10-21"
      cert_valid_to       = "2026-10-21"

      country             = "RO"
      state               = "Bucharest"
      locality            = "Bucharest"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "20:f3:68:5d:b7:e4:62:21:f6:36:a2:3e:51:e2:3a:64"
      )
}
