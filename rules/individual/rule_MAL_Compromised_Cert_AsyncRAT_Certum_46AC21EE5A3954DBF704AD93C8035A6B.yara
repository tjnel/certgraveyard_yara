import "pe"

rule MAL_Compromised_Cert_AsyncRAT_Certum_46AC21EE5A3954DBF704AD93C8035A6B {
   meta:
      description         = "Detects AsyncRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-06"
      version             = "1.0"

      hash                = "ae3811913d691d0327fb5a3dd0ee0c7918bc163fcc7aeda31da319fa7978ec14"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Open Source Developer Eman Ibrahim"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "46:ac:21:ee:5a:39:54:db:f7:04:ad:93:c8:03:5a:6b"
      cert_thumbprint     = "673309F97BE9610F9717FA16FF2B273A464DB621"
      cert_valid_from     = "2026-05-06"
      cert_valid_to       = "2027-05-06"

      country             = "EG"
      state               = "Cairo"
      locality            = "Cairo"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "46:ac:21:ee:5a:39:54:db:f7:04:ad:93:c8:03:5a:6b"
      )
}
