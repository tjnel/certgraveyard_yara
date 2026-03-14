import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_1452A7543159FF8B16C659C26435CD11 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-19"
      version             = "1.0"

      hash                = "3d44dbcec3a85de9002a82e9db9b1009dd55ffd94f456ad55be08a73b6591c8b"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "John Latino"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "14:52:a7:54:31:59:ff:8b:16:c6:59:c2:64:35:cd:11"
      cert_thumbprint     = "1FF43D472CEC8F474C36EAF48B5F8EEA836962AD"
      cert_valid_from     = "2025-12-19"
      cert_valid_to       = "2026-12-18"

      country             = "US"
      state               = "California"
      locality            = "Arnold"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "14:52:a7:54:31:59:ff:8b:16:c6:59:c2:64:35:cd:11"
      )
}
