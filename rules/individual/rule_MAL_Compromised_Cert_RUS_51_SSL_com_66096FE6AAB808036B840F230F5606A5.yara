import "pe"

rule MAL_Compromised_Cert_RUS_51_SSL_com_66096FE6AAB808036B840F230F5606A5 {
   meta:
      description         = "Detects RUS-51 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-25"
      version             = "1.0"

      hash                = "88fce5bc260870ef6296c4c5967449d0dc38e83b3fcfea5a971446e8dfd1f5ff"
      malware             = "RUS-51"
      malware_type        = "Unknown"
      malware_notes       = "Fake IT Support tool written in German used to steal credentials."

      signer              = "YOUR CHANCE j.d.o.o"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "66:09:6f:e6:aa:b8:08:03:6b:84:0f:23:0f:56:06:a5"
      cert_thumbprint     = "D65441BCFFBBBB28A38F7244CA7744ED91E6F93F"
      cert_valid_from     = "2026-08-25"
      cert_valid_to       = "2027-08-25"

      country             = "HR"
      state               = "Zagreb"
      locality            = "Zagreb"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "66:09:6f:e6:aa:b8:08:03:6b:84:0f:23:0f:56:06:a5"
      )
}
