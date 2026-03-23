import "pe"

rule MAL_Compromised_Cert_FakeDocument_SSL_com_6ECCC78826E405A2B5E09EAED8439926 {
   meta:
      description         = "Detects FakeDocument with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-27"
      version             = "1.0"

      hash                = "ae6f0329356265d5c8bab47894627cc9009849aa2a0161d919b34369f94e8146"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installer disguised as a invoice"

      signer              = "Scandinavian Beautyline AB"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6e:cc:c7:88:26:e4:05:a2:b5:e0:9e:ae:d8:43:99:26"
      cert_thumbprint     = "D2F68CE9131D9754C3854F0F60AAA5DA1777B72F"
      cert_valid_from     = "2026-01-27"
      cert_valid_to       = "2027-01-27"

      country             = "SE"
      state               = "Stockholm County"
      locality            = "Järfälla kommun"
      email               = "???"
      rdn_serial_number   = "559473-3270"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6e:cc:c7:88:26:e4:05:a2:b5:e0:9e:ae:d8:43:99:26"
      )
}
