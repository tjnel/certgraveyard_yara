import "pe"

rule MAL_Compromised_Cert_IcedID_SSL_com_698FF388ADB50B88AFB832E76B0A0AD1 {
   meta:
      description         = "Detects IcedID with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-01-30"
      version             = "1.0"

      hash                = "17014299f399f71d1d6bed136b8c624a366b222166e692522d14e2bba70bb79f"
      malware             = "IcedID"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BELLAP LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "69:8f:f3:88:ad:b5:0b:88:af:b8:32:e7:6b:0a:0a:d1"
      cert_thumbprint     = "479e01dde7e7529ed4ad111a2d7b3b16fdc6fbe2ed0d6ff015c1c823ca0939db"
      cert_valid_from     = "2023-01-30"
      cert_valid_to       = "2023-12-18"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "69:8f:f3:88:ad:b5:0b:88:af:b8:32:e7:6b:0a:0a:d1"
      )
}
