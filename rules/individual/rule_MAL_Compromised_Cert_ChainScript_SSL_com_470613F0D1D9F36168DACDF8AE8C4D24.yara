import "pe"

rule MAL_Compromised_Cert_ChainScript_SSL_com_470613F0D1D9F36168DACDF8AE8C4D24 {
   meta:
      description         = "Detects ChainScript with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-19"
      version             = "1.0"

      hash                = "26d6fa845d4f76674f96deb7e3f01a610d9224a103baf8d395d7eab16fc3fe61"
      malware             = "ChainScript"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AQUAMARINE ALLIANCE s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "47:06:13:f0:d1:d9:f3:61:68:da:cd:f8:ae:8c:4d:24"
      cert_thumbprint     = "7ae605919a7f6c2ea788a1f90814160c222ff984"
      cert_valid_from     = "2026-02-19"
      cert_valid_to       = "2027-02-19"

      country             = "CZ"
      state               = "Jihomoravský kraj"
      locality            = "Brno"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "47:06:13:f0:d1:d9:f3:61:68:da:cd:f8:ae:8c:4d:24"
      )
}
