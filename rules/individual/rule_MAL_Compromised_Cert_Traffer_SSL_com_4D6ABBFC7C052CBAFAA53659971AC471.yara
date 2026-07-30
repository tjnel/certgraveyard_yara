import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_4D6ABBFC7C052CBAFAA53659971AC471 {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-13"
      version             = "1.0"

      hash                = "c7df8e56e8bb942ed7823a3222eb22040893cbd4a5a8506609f11e0140cec5f6"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BARNEHAGEN GUNHILDS MINNE AS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4d:6a:bb:fc:7c:05:2c:ba:fa:a5:36:59:97:1a:c4:71"
      cert_thumbprint     = "12730A7DD9AF98F14441D476C10EB346708C1194"
      cert_valid_from     = "2026-07-13"
      cert_valid_to       = "2027-07-13"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "4d:6a:bb:fc:7c:05:2c:ba:fa:a5:36:59:97:1a:c4:71"
      )
}
