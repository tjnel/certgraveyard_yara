import "pe"

rule MAL_Compromised_Cert_CrocoRAT_SSL_com_473D28E38B9BC50ABE922C40C214810C {
   meta:
      description         = "Detects CrocoRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-24"
      version             = "1.0"

      hash                = "de35dd440f4b55682b015290ce207b944b95ea8d4e2ff23023bcbd025c31d9a2"
      malware             = "CrocoRAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "SOPHISTICATED SOFTWARES (PTY) LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "47:3d:28:e3:8b:9b:c5:0a:be:92:2c:40:c2:14:81:0c"
      cert_thumbprint     = "3c32afd70432f070d996eaaa946ebe79273f98c8"
      cert_valid_from     = "2026-06-24"
      cert_valid_to       = "2027-06-24"

      country             = "ZA"
      state               = "Free State"
      locality            = "Virginia"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "47:3d:28:e3:8b:9b:c5:0a:be:92:2c:40:c2:14:81:0c"
      )
}
