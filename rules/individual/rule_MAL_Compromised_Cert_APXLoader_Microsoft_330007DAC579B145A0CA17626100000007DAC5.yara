import "pe"

rule MAL_Compromised_Cert_APXLoader_Microsoft_330007DAC579B145A0CA17626100000007DAC5 {
   meta:
      description         = "Detects APXLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-04"
      version             = "1.0"

      hash                = "6efda8849ca8afc2849448764c283bb1e3f1f1e56d406eb9a8a831c5701cc9b0"
      malware             = "APXLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "Vic Thadhani"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:da:c5:79:b1:45:a0:ca:17:62:61:00:00:00:07:da:c5"
      cert_thumbprint     = "89B85BC28B6CEB366AC2EB64AF380D578BABD54E"
      cert_valid_from     = "2026-04-04"
      cert_valid_to       = "2026-04-07"

      country             = "US"
      state               = "California"
      locality            = "PALO ALTO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:da:c5:79:b1:45:a0:ca:17:62:61:00:00:00:07:da:c5"
      )
}
