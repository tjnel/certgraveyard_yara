import "pe"

rule MAL_Compromised_Cert_TrashAgent_SSL_com_50371174E52213DCD4654A44F7A4F515 {
   meta:
      description         = "Detects TrashAgent with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-24"
      version             = "1.0"

      hash                = "0d2c1adf36df47199ee1ca42417660ac5027f77671d4f3c59cce0c23d94e25f8"
      malware             = "TrashAgent"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware uses a custom UserAgent string TrashAgent. They use trojanized versions of applications for their malware and present a consistent error as anti-analysis."

      signer              = "Hydraterm AB"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "50:37:11:74:e5:22:13:dc:d4:65:4a:44:f7:a4:f5:15"
      cert_thumbprint     = "38C81FCCAA01021F13DACD758104A5F0C718DB40"
      cert_valid_from     = "2025-11-24"
      cert_valid_to       = "2028-11-23"

      country             = "SE"
      state               = "Kronoberg County"
      locality            = "Växjö Kommun"
      email               = "???"
      rdn_serial_number   = "559337-1924"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "50:37:11:74:e5:22:13:dc:d4:65:4a:44:f7:a4:f5:15"
      )
}
