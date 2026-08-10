import "pe"

rule MAL_Compromised_Cert_Trojan_Win32_DefenderPlug_Keylogger_SSL_com_3D7B3B375FE1434665CBF43EF2119168 {
   meta:
      description         = "Detects Trojan:Win32/DefenderPlug.Keylogger with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-08"
      version             = "1.0"

      hash                = "5f80100560c0422cfd71a5138d65f1124287d2bf9f941c33add56ee9626b071b"
      malware             = "Trojan:Win32/DefenderPlug.Keylogger"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Osh Spetsstroy LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3d:7b:3b:37:5f:e1:43:46:65:cb:f4:3e:f2:11:91:68"
      cert_thumbprint     = "22c8e30de6cc2f32514967c2d12e18adbd8315da"
      cert_valid_from     = "2026-07-08"
      cert_valid_to       = "2027-07-08"

      country             = "KG"
      state               = "Osh Region"
      locality            = "Jylkeldi"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3d:7b:3b:37:5f:e1:43:46:65:cb:f4:3e:f2:11:91:68"
      )
}
