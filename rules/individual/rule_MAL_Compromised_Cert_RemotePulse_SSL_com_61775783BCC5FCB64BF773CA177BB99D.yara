import "pe"

rule MAL_Compromised_Cert_RemotePulse_SSL_com_61775783BCC5FCB64BF773CA177BB99D {
   meta:
      description         = "Detects RemotePulse with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-26"
      version             = "1.0"

      hash                = "bd14c4f23f597ced87a2a57cc0b360d50fe916267b2878727ed1bbbd7b751f41"
      malware             = "RemotePulse"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "EIKON S.A."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "61:77:57:83:bc:c5:fc:b6:4b:f7:73:ca:17:7b:b9:9d"
      cert_thumbprint     = "AD4213CD9F8A4210959D036078B7FBD6777E7FF6"
      cert_valid_from     = "2025-09-26"
      cert_valid_to       = "2026-09-26"

      country             = "EC"
      state               = "Guayas Province"
      locality            = "Guayaquil"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "61:77:57:83:bc:c5:fc:b6:4b:f7:73:ca:17:7b:b9:9d"
      )
}
