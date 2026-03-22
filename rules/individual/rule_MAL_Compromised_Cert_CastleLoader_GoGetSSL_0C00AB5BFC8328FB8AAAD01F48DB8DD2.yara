import "pe"

rule MAL_Compromised_Cert_CastleLoader_GoGetSSL_0C00AB5BFC8328FB8AAAD01F48DB8DD2 {
   meta:
      description         = "Detects CastleLoader with compromised cert (GoGetSSL)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-03"
      version             = "1.0"

      hash                = "bc8cb64c089415ccc2bfd9d29bf74fe06ae5e3b0493a336412184d20ac774604"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: briskbeverage[.]com"

      signer              = "TECHNOLOGY APPRAISALS LIMITED"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "0c:00:ab:5b:fc:83:28:fb:8a:aa:d0:1f:48:db:8d:d2"
      cert_thumbprint     = "778DB28F1B779AD4DC895055287084A5533064F0"
      cert_valid_from     = "2026-03-03"
      cert_valid_to       = "2027-03-02"

      country             = "GB"
      state               = "???"
      locality            = "Twickenham"
      email               = "???"
      rdn_serial_number   = "01850356"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "0c:00:ab:5b:fc:83:28:fb:8a:aa:d0:1f:48:db:8d:d2"
      )
}
