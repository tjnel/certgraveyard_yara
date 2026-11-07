import "pe"

rule MAL_Compromised_Cert_FakeRDCMan_SSL_com_4C7472DAADA7CBA21B042C39621359A7 {
   meta:
      description         = "Detects FakeRDCMan with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-06"
      version             = "1.0"

      hash                = "2da933512eafaaf376bd5b9b15820971dcd01f5beffc495f4011af32828796c7"
      malware             = "FakeRDCMan"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Emmanuel Anderson"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4c:74:72:da:ad:a7:cb:a2:1b:04:2c:39:62:13:59:a7"
      cert_thumbprint     = "d0469e0c2c69be916faa2a00d6907e406ba157d5"
      cert_valid_from     = "2026-10-06"
      cert_valid_to       = "2027-10-06"

      country             = "US"
      state               = "Virginia"
      locality            = "Richmond"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "4c:74:72:da:ad:a7:cb:a2:1b:04:2c:39:62:13:59:a7"
      )
}
