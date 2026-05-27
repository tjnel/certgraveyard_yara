import "pe"

rule MAL_Compromised_Cert_MiniFast_SSL_com_37D7A8335ECDAA62E6A4E709CA43ADD8 {
   meta:
      description         = "Detects MiniFast with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-26"
      version             = "1.0"

      hash                = "2c214494fd0bad31473ca8adce78a4f50847876584571e66aadeae70827ec2dc"
      malware             = "MiniFast"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kirubel Kerie Negeya"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "37:d7:a8:33:5e:cd:aa:62:e6:a4:e7:09:ca:43:ad:d8"
      cert_thumbprint     = "A7B7D27448F4B248FDDCB3E2635077AF00B5C7D1"
      cert_valid_from     = "2026-03-26"
      cert_valid_to       = "2027-03-25"

      country             = "ET"
      state               = "Addis Ababa"
      locality            = "Addis Ababa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "37:d7:a8:33:5e:cd:aa:62:e6:a4:e7:09:ca:43:ad:d8"
      )
}
