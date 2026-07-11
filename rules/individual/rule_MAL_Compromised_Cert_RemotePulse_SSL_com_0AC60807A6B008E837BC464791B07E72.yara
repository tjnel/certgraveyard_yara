import "pe"

rule MAL_Compromised_Cert_RemotePulse_SSL_com_0AC60807A6B008E837BC464791B07E72 {
   meta:
      description         = "Detects RemotePulse with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "2f6b84a90d8b9440dfd465f79d59f9581835f4e46143f16243b348cb3ac53f2d"
      malware             = "RemotePulse"
      malware_type        = "Remote access tool"
      malware_notes       = "Fake RMM tool being sold via Telegram."

      signer              = "VESALII COMPUTER SYSTEMS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0a:c6:08:07:a6:b0:08:e8:37:bc:46:47:91:b0:7e:72"
      cert_thumbprint     = "CE09B25F94D9C4C966812C5E2A608EC3437DE1DF"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-01-08"

      country             = "AE"
      state               = "Dubai"
      locality            = "Dubai"
      email               = "???"
      rdn_serial_number   = "BL3396"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0a:c6:08:07:a6:b0:08:e8:37:bc:46:47:91:b0:7e:72"
      )
}
