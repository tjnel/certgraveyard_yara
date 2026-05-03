import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_330007EE11DAE1E4AAA0899D5C00000007EE11 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-22"
      version             = "1.0"

      hash                = "e6b847a3cfeae0e63cd47d25e79e40fea5c53cccd11193b0282b42dd53d80378"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:ee:11:da:e1:e4:aa:a0:89:9d:5c:00:00:00:07:ee:11"
      cert_thumbprint     = "AC12217249131C14A62060E102790EBECB64CE27"
      cert_valid_from     = "2026-02-22"
      cert_valid_to       = "2026-02-25"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:ee:11:da:e1:e4:aa:a0:89:9d:5c:00:00:00:07:ee:11"
      )
}
