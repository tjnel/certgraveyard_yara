import "pe"

rule MAL_Compromised_Cert_FakeTrading_SSL_com_50736A370250FC80E523D41A25D996C9 {
   meta:
      description         = "Detects FakeTrading with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-10"
      version             = "1.0"

      hash                = "7ca430feaf3e25c56d5084766373b04538c9256fab4c2525ffd58a45a866eee0"
      malware             = "FakeTrading"
      malware_type        = "Unknown"
      malware_notes       = "Malware targeting crypto traders impersonating known trading platforms. Ex: cvistaapp.com"

      signer              = "TRUST & SIGN POLAND SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "50:73:6a:37:02:50:fc:80:e5:23:d4:1a:25:d9:96:c9"
      cert_thumbprint     = "E8783C46EE7080099C2961FDE4ECD47801EF3351"
      cert_valid_from     = "2026-03-10"
      cert_valid_to       = "2026-08-22"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "50:73:6a:37:02:50:fc:80:e5:23:d4:1a:25:d9:96:c9"
      )
}
