import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Microsoft_330000B80523BEB847F3BD8D4900000000B805 {
   meta:
      description         = "Detects Certificate warming with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-03"
      version             = "1.0"

      hash                = "6d844f31ce6fa601e701d76887f7308ca4dda629fd4ed7189d9d43b1e397529c"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = "This certificate is being 'warmed' by being used to sign benign things before signing malware."

      signer              = "Minh Tran"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:b8:05:23:be:b8:47:f3:bd:8d:49:00:00:00:00:b8:05"
      cert_thumbprint     = "A0EFCB3B300530E92DBBEE253A5834D110E96715"
      cert_valid_from     = "2026-05-03"
      cert_valid_to       = "2026-05-06"

      country             = "US"
      state               = "Texas"
      locality            = "Grand Prairie"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:b8:05:23:be:b8:47:f3:bd:8d:49:00:00:00:00:b8:05"
      )
}
