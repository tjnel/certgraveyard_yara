import "pe"

rule MAL_Compromised_Cert_UpdateLogger_SSL_com_89124B0BE12EEBB6BB173F40FE91754 {
   meta:
      description         = "Detects UpdateLogger with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-16"
      version             = "1.0"

      hash                = "cfe976aa42a6c1d8e99098aff4124c6799ba210bc936173d8bd7a55ead45f620"
      malware             = "UpdateLogger"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BEST FIREWOOD BALTIC OU"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "89:12:4b:0b:e1:2e:eb:b6:bb:17:3f:40:fe:91:75:4"
      cert_thumbprint     = "539a60179043717a01a64fa7b6b187b6410aeb70"
      cert_valid_from     = "2026-10-16"
      cert_valid_to       = "2027-10-16"

      country             = "EE"
      state               = "Harju County"
      locality            = "Tallinn"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "89:12:4b:0b:e1:2e:eb:b6:bb:17:3f:40:fe:91:75:4"
      )
}
