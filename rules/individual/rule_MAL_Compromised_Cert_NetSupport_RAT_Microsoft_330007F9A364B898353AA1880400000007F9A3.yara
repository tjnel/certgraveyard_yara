import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Microsoft_330007F9A364B898353AA1880400000007F9A3 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-24"
      version             = "1.0"

      hash                = "cf2af45ffe7606c816f473c0e9783e3db0c3bcd05ec7b57d94f4759ff5451b46"
      malware             = "NetSupport RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ricardo Reis"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:f9:a3:64:b8:98:35:3a:a1:88:04:00:00:00:07:f9:a3"
      cert_thumbprint     = "8187F4B5EA3081C23D43A89321655CDCB73CE548"
      cert_valid_from     = "2026-02-24"
      cert_valid_to       = "2026-02-27"

      country             = "US"
      state               = "South Carolina"
      locality            = "Johnston"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:f9:a3:64:b8:98:35:3a:a1:88:04:00:00:00:07:f9:a3"
      )
}
