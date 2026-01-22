import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_4F10DF22BF708616F9437AB06E0FAAB0 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-19"
      version             = "1.0"

      hash                = "460e2568c1198ace18c12d70ac5328dbd07bef3497e2b199afebea31610c8b47"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "UMNOTHO SOFTWARE SA CC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4f:10:df:22:bf:70:86:16:f9:43:7a:b0:6e:0f:aa:b0"
      cert_thumbprint     = "61D0362B8C735DAE6B6715A25707BEE03FA98A7A"
      cert_valid_from     = "2025-11-19"
      cert_valid_to       = "2026-11-18"

      country             = "ZA"
      state               = "KwaZulu-Natal"
      locality            = "Melmoth"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "4f:10:df:22:bf:70:86:16:f9:43:7a:b0:6e:0f:aa:b0"
      )
}
