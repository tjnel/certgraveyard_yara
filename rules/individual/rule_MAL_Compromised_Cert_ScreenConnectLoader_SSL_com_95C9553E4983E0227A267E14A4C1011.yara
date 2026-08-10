import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_95C9553E4983E0227A267E14A4C1011 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-29"
      version             = "1.0"

      hash                = "04b5b38b7720cc502d4ea901830f8f50516c16ead65ab50b173af083e41c180d"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Christian Torres"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "95:c9:55:3e:49:83:e0:22:7a:26:7e:14:a4:c1:01:1"
      cert_thumbprint     = "6f0a39bb615326099c01118093a17f2e09388506"
      cert_valid_from     = "2026-06-29"
      cert_valid_to       = "2027-06-29"

      country             = "US"
      state               = "Texas"
      locality            = "Universal City"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "95:c9:55:3e:49:83:e0:22:7a:26:7e:14:a4:c1:01:1"
      )
}
