import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_22A5CF785D165B31ECFA4616E05C31C7 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-22"
      version             = "1.0"

      hash                = "8099e85c4aa05f50ff299a130dc26a67b45aed519668e8b1ee1692e0034196c2"
      malware             = "NetSupport RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Flagship Promotion s. r. o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "22:a5:cf:78:5d:16:5b:31:ec:fa:46:16:e0:5c:31:c7"
      cert_thumbprint     = "76A522257D09EC3F41B0431AAE2D8CE7F81B427E"
      cert_valid_from     = "2026-01-22"
      cert_valid_to       = "2027-01-22"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "22:a5:cf:78:5d:16:5b:31:ec:fa:46:16:e0:5c:31:c7"
      )
}
