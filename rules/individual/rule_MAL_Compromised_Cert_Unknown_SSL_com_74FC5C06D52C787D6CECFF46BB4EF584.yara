import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_74FC5C06D52C787D6CECFF46BB4EF584 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-19"
      version             = "1.0"

      hash                = "2143baefd0b108fa1f6cfcfa3eb31d87578c6014117768f06bd8544dd02c8adf"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "Downloads python, execute arbitrary payloads retrieved from insharedata[.]org/check.php/api/launcher/14/payload?direct=1"

      signer              = "F & P PARTNERS LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "74:fc:5c:06:d5:2c:78:7d:6c:ec:ff:46:bb:4e:f5:84"
      cert_thumbprint     = "F052A5F675315F7A0412E8652DFECA9842760518"
      cert_valid_from     = "2026-05-19"
      cert_valid_to       = "2027-04-30"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "74:fc:5c:06:d5:2c:78:7d:6c:ec:ff:46:bb:4e:f5:84"
      )
}
