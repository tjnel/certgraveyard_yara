import "pe"

rule MAL_Compromised_Cert_MacSync_Apple_29A552D8DFF80468 {
   meta:
      description         = "Detects MacSync with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-14"
      version             = "1.0"

      hash                = "7cfe0b119e616ac81ddb1767a5c7f40bec67d91fdd66e53490c0225789537073"
      malware             = "MacSync"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OKAN ATAKOL"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "29:a5:52:d8:df:f8:04:68"
      cert_thumbprint     = "0401D7DA62746F5A8A5AA38D46B995EEDDFE0361"
      cert_valid_from     = "2025-11-14"
      cert_valid_to       = "2027-02-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "29:a5:52:d8:df:f8:04:68"
      )
}
