import "pe"

rule MAL_Compromised_Cert_Certificate_warming_SSL_com_4CE56A1FAD8F3678CF465B32174E5A9F {
   meta:
      description         = "Detects Certificate warming with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-29"
      version             = "1.0"

      hash                = "cc4190819ca8193faab7b0852e7e65a065f4968448d88b706aa297fb1d1505c1"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OsOO \"BAGYT MEYKIN\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4c:e5:6a:1f:ad:8f:36:78:cf:46:5b:32:17:4e:5a:9f"
      cert_thumbprint     = "b186a7dd63355ffa3635b80658ab7ddf85346ede"
      cert_valid_from     = "2026-06-29"
      cert_valid_to       = "2027-06-29"

      country             = "KG"
      state               = "Osh Region"
      locality            = "Kara Suu"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4c:e5:6a:1f:ad:8f:36:78:cf:46:5b:32:17:4e:5a:9f"
      )
}
