import "pe"

rule MAL_Compromised_Cert_Abe_RAT_SSL_com_5CA1AA263B09E43D349B735343EB2FDC {
   meta:
      description         = "Detects Abe RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-26"
      version             = "1.0"

      hash                = "eda3e8e4e87ccb0423886ae5cfd1d488481d4ce16ab5b5efdfbce6f9f1a35dd9"
      malware             = "Abe RAT"
      malware_type        = "Unknown"
      malware_notes       = "https://rogueauthority.org/signed-abe-office-agent-hidden-browser-stealer"

      signer              = "Kimberley Hankinson"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "5c:a1:aa:26:3b:09:e4:3d:34:9b:73:53:43:eb:2f:dc"
      cert_thumbprint     = "cc6851101f0bbd092b1f34472a294e16b3ee99e0"
      cert_valid_from     = "2026-10-26"
      cert_valid_to       = "2027-10-26"

      country             = "US"
      state               = "Pennsylvania"
      locality            = "Cherry Tree"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "5c:a1:aa:26:3b:09:e4:3d:34:9b:73:53:43:eb:2f:dc"
      )
}
