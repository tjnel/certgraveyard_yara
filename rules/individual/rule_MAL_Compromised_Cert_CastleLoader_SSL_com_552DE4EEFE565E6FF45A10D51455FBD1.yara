import "pe"

rule MAL_Compromised_Cert_CastleLoader_SSL_com_552DE4EEFE565E6FF45A10D51455FBD1 {
   meta:
      description         = "Detects CastleLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-10"
      version             = "1.0"

      hash                = "1c1170c2520f21090e8bba1ae45c8bc076940d45def8072eb3d1b8c3d97030d1"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: myltexa[.]com"

      signer              = "RICE DATA COM LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "55:2d:e4:ee:fe:56:5e:6f:f4:5a:10:d5:14:55:fb:d1"
      cert_thumbprint     = "228CAA406C15C10E0E758A15BF0BC0455D6AB6AC"
      cert_valid_from     = "2026-06-10"
      cert_valid_to       = "2027-06-10"

      country             = "US"
      state               = "Florida"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "55:2d:e4:ee:fe:56:5e:6f:f4:5a:10:d5:14:55:fb:d1"
      )
}
