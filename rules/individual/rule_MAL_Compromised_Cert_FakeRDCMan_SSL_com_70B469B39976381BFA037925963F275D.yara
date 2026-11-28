import "pe"

rule MAL_Compromised_Cert_FakeRDCMan_SSL_com_70B469B39976381BFA037925963F275D {
   meta:
      description         = "Detects FakeRDCMan with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-01"
      version             = "1.0"

      hash                = "ec2457d6b7baf73f4936a02886c1f466daa7e8028e9beaafd1d717fddc6453bc"
      malware             = "FakeRDCMan"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Johnathon Shepherd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "70:b4:69:b3:99:76:38:1b:fa:03:79:25:96:3f:27:5d"
      cert_thumbprint     = "d32792ffcc12e7eb5b67d9361999acb594c5666e"
      cert_valid_from     = "2026-11-01"
      cert_valid_to       = "2027-11-01"

      country             = "US"
      state               = "Kentucky"
      locality            = "Saint Catharine"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "70:b4:69:b3:99:76:38:1b:fa:03:79:25:96:3f:27:5d"
      )
}
