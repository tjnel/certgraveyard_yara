import "pe"

rule MAL_Compromised_Cert_StatusLoader_SSL_com_666EABB70B4BFCCA1E0DE0BF3256CB4B {
   meta:
      description         = "Detects StatusLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-07"
      version             = "1.0"

      hash                = "8da2ad369527e360b5d4e3970b9340ba81831dd37f4852a5d8a82bfa03d63886"
      malware             = "StatusLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Prospere Software Sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "66:6e:ab:b7:0b:4b:fc:ca:1e:0d:e0:bf:32:56:cb:4b"
      cert_thumbprint     = "474C70712413735AF91AE7383A1F7FA918229457"
      cert_valid_from     = "2025-01-07"
      cert_valid_to       = "2026-01-07"

      country             = "PL"
      state               = "Podkarpackie Voivodeship"
      locality            = "Rzeszów"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "66:6e:ab:b7:0b:4b:fc:ca:1e:0d:e0:bf:32:56:cb:4b"
      )
}
