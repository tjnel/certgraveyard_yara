import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_3300070C7A2B04CE4F071E4928000000070C7A {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-22"
      version             = "1.0"

      hash                = "18cb2495b5e0512f8026d7fd123ae821d554d918ecd7269e9b8eb40ca2f480cc"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "C2: cybernetvillage[.]com"

      signer              = "Julie Jorgensen"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:0c:7a:2b:04:ce:4f:07:1e:49:28:00:00:00:07:0c:7a"
      cert_thumbprint     = "7464F97100FB5398F1DADB3C14F25E63BBB68415"
      cert_valid_from     = "2026-02-22"
      cert_valid_to       = "2026-02-25"

      country             = "US"
      state               = "Maryland"
      locality            = "BALTIMORE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:0c:7a:2b:04:ce:4f:07:1e:49:28:00:00:00:07:0c:7a"
      )
}
