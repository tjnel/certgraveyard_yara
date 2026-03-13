import "pe"

rule MAL_Compromised_Cert_FakeTrading_SSL_com_6B902553D4FAA01CD0FA62009C8F2DB2 {
   meta:
      description         = "Detects FakeTrading with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-22"
      version             = "1.0"

      hash                = "18535509a6d259487b6b06edf2f1b2df3c4890fe16d630c8a2ec6af32cbe8b32"
      malware             = "FakeTrading"
      malware_type        = "Unknown"
      malware_notes       = "Malware targeting crypto traders impersonating known trading platforms. Ex: c-vistaapp[.]com"

      signer              = "TRUST & SIGN POLAND SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6b:90:25:53:d4:fa:a0:1c:d0:fa:62:00:9c:8f:2d:b2"
      cert_thumbprint     = "2227DF3893A02B43B826A10A17E0F88E5B9448AB"
      cert_valid_from     = "2025-08-22"
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
         sig.serial == "6b:90:25:53:d4:fa:a0:1c:d0:fa:62:00:9c:8f:2d:b2"
      )
}
