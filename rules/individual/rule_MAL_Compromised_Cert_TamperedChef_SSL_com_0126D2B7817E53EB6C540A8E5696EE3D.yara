import "pe"

rule MAL_Compromised_Cert_TamperedChef_SSL_com_0126D2B7817E53EB6C540A8E5696EE3D {
   meta:
      description         = "Detects TamperedChef with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-09-17"
      version             = "1.0"

      hash                = "30e5227a3aded0ed65300d7853978d132a12801e2e0a95273bdfe1c52f98c3f8"
      malware             = "TamperedChef"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SmileMotion PTE. LTD."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "01:26:d2:b7:81:7e:53:eb:6c:54:0a:8e:56:96:ee:3d"
      cert_thumbprint     = "488047C8D639B8A8327C985EABCCB6FD9389E7FA"
      cert_valid_from     = "2021-09-17"
      cert_valid_to       = "2024-09-16"

      country             = "SG"
      state               = "???"
      locality            = "Singapore"
      email               = "???"
      rdn_serial_number   = "202032098W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "01:26:d2:b7:81:7e:53:eb:6c:54:0a:8e:56:96:ee:3d"
      )
}
