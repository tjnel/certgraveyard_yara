import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_SSL_com_4824B75744F606DCEEF3A06D638FFDA2 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-18"
      version             = "1.0"

      hash                = "f1a9b7ca2235fc2c7642fff339782a184835ed6ab0d971690c079bbefc9a85c5"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Portier Global Pty Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "48:24:b7:57:44:f6:06:dc:ee:f3:a0:6d:63:8f:fd:a2"
      cert_thumbprint     = "61D8BED5A5007F3DA29EB18ABB18CF75EB102FD1"
      cert_valid_from     = "2023-12-18"
      cert_valid_to       = "2026-12-17"

      country             = "AU"
      state               = "Queensland"
      locality            = "Little Mountain"
      email               = "???"
      rdn_serial_number   = "86 672 385 661"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "48:24:b7:57:44:f6:06:dc:ee:f3:a0:6d:63:8f:fd:a2"
      )
}
