import "pe"

rule MAL_Compromised_Cert_FakeTrading_SSL_com_084DF03CC7D8CAF34C5C2CFEEC448B27 {
   meta:
      description         = "Detects FakeTrading with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-04"
      version             = "1.0"

      hash                = "87c266e14685da69531d6e6fd8128c8727a4e28cdc372a6b84718d85c804c705"
      malware             = "FakeTrading"
      malware_type        = "Unknown"
      malware_notes       = "Malware targeting crypto traders impersonating known trading platforms. Ex: cvistaapp.com"

      signer              = "TRUST & SIGN POLAND SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "08:4d:f0:3c:c7:d8:ca:f3:4c:5c:2c:fe:ec:44:8b:27"
      cert_thumbprint     = "9E11AEFF83F1166C22952579143103D9379C9A13"
      cert_valid_from     = "2026-03-04"
      cert_valid_to       = "2026-08-22"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "08:4d:f0:3c:c7:d8:ca:f3:4c:5c:2c:fe:ec:44:8b:27"
      )
}
