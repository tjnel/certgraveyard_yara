import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_1110B32029ED01AEC9767F2FA49A2132 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-08"
      version             = "1.0"

      hash                = "af3c15aaf209ad95c33f36170cd7685f306010e0e425966fb7cbab64a5e6d536"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Christian Torres"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "11:10:b3:20:29:ed:01:ae:c9:76:7f:2f:a4:9a:21:32"
      cert_thumbprint     = "ed0b41ec7b7f9e271ebebd9e75985326ebd98711"
      cert_valid_from     = "2026-07-08"
      cert_valid_to       = "2027-07-08"

      country             = "US"
      state               = "Texas"
      locality            = "Universal City"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "11:10:b3:20:29:ed:01:ae:c9:76:7f:2f:a4:9a:21:32"
      )
}
