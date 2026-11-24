import "pe"

rule MAL_Compromised_Cert_HijackLoader_SSL_com_2185A35B6F46B7DCD9E4994E71B8EFEA {
   meta:
      description         = "Detects HijackLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-20"
      version             = "1.0"

      hash                = "25e0264394fd3fb6ab8a37216b32e394614757c0ba26f2ffd582372fa16296f3"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: randomrandomicanseeyou[.]com"

      signer              = "Iperia Newell"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "21:85:a3:5b:6f:46:b7:dc:d9:e4:99:4e:71:b8:ef:ea"
      cert_thumbprint     = "a60aae4464b69a0da3518ba49f58b53043afdbf4"
      cert_valid_from     = "2026-10-20"
      cert_valid_to       = "2027-10-20"

      country             = "US"
      state               = "Indiana"
      locality            = "Fort Wayne"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "21:85:a3:5b:6f:46:b7:dc:d9:e4:99:4e:71:b8:ef:ea"
      )
}
