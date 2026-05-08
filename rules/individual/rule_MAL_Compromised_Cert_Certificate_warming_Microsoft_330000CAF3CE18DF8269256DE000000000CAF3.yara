import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Microsoft_330000CAF3CE18DF8269256DE000000000CAF3 {
   meta:
      description         = "Detects Certificate warming with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-05"
      version             = "1.0"

      hash                = "c632ac50aaea1b3243b6d630e8a54ec30881c375b67a9b2eb838f1edf0a9a4c5"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = "This certificate is being 'warmed' by signing benign files before signing malware."

      signer              = "Thomas Sullivan"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:ca:f3:ce:18:df:82:69:25:6d:e0:00:00:00:00:ca:f3"
      cert_thumbprint     = "C8D4B037ED40917A7C96C6C090436023501C95F0"
      cert_valid_from     = "2026-05-05"
      cert_valid_to       = "2026-05-08"

      country             = "US"
      state               = "California"
      locality            = "San Anselmo"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:ca:f3:ce:18:df:82:69:25:6d:e0:00:00:00:00:ca:f3"
      )
}
