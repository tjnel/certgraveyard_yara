import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_2480ADFCAEF3FFECD368D261F0F83FA {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-24"
      version             = "1.0"

      hash                = "6107d0c501722579516c9046671e46b8d708af87b9b95eda5c76d16d44baf0ae"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Fake Streamyard"

      signer              = "Xiamen Weixiang Animation Design Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "24:80:ad:fc:ae:f3:ff:ec:d3:68:d2:61:f0:f8:3f:a"
      cert_thumbprint     = "3ed3a17061faabe8ce35767cf9990eb5df6d2bdb"
      cert_valid_from     = "2026-03-24"
      cert_valid_to       = "2027-03-24"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "24:80:ad:fc:ae:f3:ff:ec:d3:68:d2:61:f0:f8:3f:a"
      )
}
