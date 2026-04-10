import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_SSL_com_1144335932C394E43644A300BF7A746F {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-12"
      version             = "1.0"

      hash                = "03262ae553984199273d81204e270bc9ec267e3f072154ac708e542665b58a8c"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "SIMPLE S.A."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "11:44:33:59:32:c3:94:e4:36:44:a3:00:bf:7a:74:6f"
      cert_thumbprint     = "F9CAAEDF059D7620303D5633E6EBF33E4733E419"
      cert_valid_from     = "2026-01-12"
      cert_valid_to       = "2027-11-19"

      country             = "PL"
      state               = "Mazowieckie"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "0000065743"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "11:44:33:59:32:c3:94:e4:36:44:a3:00:bf:7a:74:6f"
      )
}
