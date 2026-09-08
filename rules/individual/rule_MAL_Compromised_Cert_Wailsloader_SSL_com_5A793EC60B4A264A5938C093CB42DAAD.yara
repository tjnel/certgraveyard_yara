import "pe"

rule MAL_Compromised_Cert_Wailsloader_SSL_com_5A793EC60B4A264A5938C093CB42DAAD {
   meta:
      description         = "Detects Wailsloader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-22"
      version             = "1.0"

      hash                = "9714e527b424152df7391a7c9dc5b3a537c77ccfcb299d85d31f48771897c52b"
      malware             = "Wailsloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Osauhing Karusoftware"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "5a:79:3e:c6:0b:4a:26:4a:59:38:c0:93:cb:42:da:ad"
      cert_thumbprint     = "2a9053d8b158dde9c2f944e8d6372071f2575052"
      cert_valid_from     = "2026-06-22"
      cert_valid_to       = "2027-06-22"

      country             = "EE"
      state               = "---"
      locality            = "Leppneeme kula"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "5a:79:3e:c6:0b:4a:26:4a:59:38:c0:93:cb:42:da:ad"
      )
}
