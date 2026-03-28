import "pe"

rule MAL_Compromised_Cert_ETDucky_FakeRMM_SSL_com_6607C6D3AA188E3EA1CEDBEC3A764F36 {
   meta:
      description         = "Detects ETDucky, FakeRMM with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-05"
      version             = "1.0"

      hash                = "eae8cd926d6e304636c68e9923bc3f8132aebf27e330ecb61c8f5c8c7e77f385"
      malware             = "ETDucky, FakeRMM"
      malware_type        = "Remote access tool"
      malware_notes       = "Company founded in Feb 2026, certificate issued in Mar 2026, abused by cybercrime before end of the month."

      signer              = "ET Ducky LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "66:07:c6:d3:aa:18:8e:3e:a1:ce:db:ec:3a:76:4f:36"
      cert_thumbprint     = "EDB66DA33B39DEC4478F27C0BF1A1F54490A3C09"
      cert_valid_from     = "2026-03-05"
      cert_valid_to       = "2027-03-05"

      country             = "US"
      state               = "Washington"
      locality            = "Bellingham"
      email               = "???"
      rdn_serial_number   = "606 084 406"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "66:07:c6:d3:aa:18:8e:3e:a1:ce:db:ec:3a:76:4f:36"
      )
}
