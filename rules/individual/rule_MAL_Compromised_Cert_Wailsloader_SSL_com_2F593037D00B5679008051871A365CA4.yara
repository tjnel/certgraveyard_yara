import "pe"

rule MAL_Compromised_Cert_Wailsloader_SSL_com_2F593037D00B5679008051871A365CA4 {
   meta:
      description         = "Detects Wailsloader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-07"
      version             = "1.0"

      hash                = "e27d133c3b29c1a0c0eca19b56dbb1db2f731db5c7b6dd3e7acacfdf49615cd3"
      malware             = "Wailsloader"
      malware_type        = "Unknown"
      malware_notes       = "Fake MFA tool used in fake support scams: https://x.com/wbmmfq/status/2110788845268795495?s=20"

      signer              = "FILIP KOZJAK"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "2f:59:30:37:d0:0b:56:79:00:80:51:87:1a:36:5c:a4"
      cert_thumbprint     = "213e6698e8b0964934908dda361e085ce4d0e102"
      cert_valid_from     = "2026-09-07"
      cert_valid_to       = "2027-09-07"

      country             = "HR"
      state               = "Zagreb"
      locality            = "Zagreb"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "2f:59:30:37:d0:0b:56:79:00:80:51:87:1a:36:5c:a4"
      )
}
