import "pe"

rule MAL_Compromised_Cert_FakeRVTools_SSL_com_38045E62CCCB2723E049C01C7A8A4B7C {
   meta:
      description         = "Detects FakeRVTools with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-20"
      version             = "1.0"

      hash                = "f16bccf97f52eba93d6ad2013520ff578d694c14bfe22953b50b5a54780b1ccb"
      malware             = "FakeRVTools"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Betty Robinson"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "38:04:5e:62:cc:cb:27:23:e0:49:c0:1c:7a:8a:4b:7c"
      cert_thumbprint     = "d2bf64e17181e23ac379afd4bd59dc259ed1b19d"
      cert_valid_from     = "2026-10-20"
      cert_valid_to       = "2027-10-20"

      country             = "US"
      state               = "Arkansas"
      locality            = "Lockesburg"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "38:04:5e:62:cc:cb:27:23:e0:49:c0:1c:7a:8a:4b:7c"
      )
}
