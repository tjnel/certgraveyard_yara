import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_60353AC688FD82A02C36C9043C8CEB09 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-28"
      version             = "1.0"

      hash                = "6bb215e9852b70c8f22996e269f5fc925b9782e12632544afce223a81ca21969"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "C2: reley[.]xevarith[.]com"

      signer              = "NURHAN KAYIR FIPACK SOLUTIONS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "60:35:3a:c6:88:fd:82:a0:2c:36:c9:04:3c:8c:eb:09"
      cert_thumbprint     = "26BC0617A970F629F2E3BB38353C3FAE3C41706A"
      cert_valid_from     = "2026-05-28"
      cert_valid_to       = "2027-05-28"

      country             = "TR"
      state               = "Istanbul Province"
      locality            = "Sancaktepe"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "60:35:3a:c6:88:fd:82:a0:2c:36:c9:04:3c:8c:eb:09"
      )
}
