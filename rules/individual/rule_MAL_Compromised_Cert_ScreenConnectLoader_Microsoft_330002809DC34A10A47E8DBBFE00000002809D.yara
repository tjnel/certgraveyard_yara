import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330002809DC34A10A47E8DBBFE00000002809D {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-29"
      version             = "1.0"

      hash                = "c972dd09d07972230bfc3282a82494c8a9ca29b48532038af8966f9c3d98564d"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Dennis Miller"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:02:80:9d:c3:4a:10:a4:7e:8d:bb:fe:00:00:00:02:80:9d"
      cert_thumbprint     = "A62F4D7E93DE08F9676E489CD0FD9FDD134D53A6"
      cert_valid_from     = "2026-06-29"
      cert_valid_to       = "2026-07-02"

      country             = "US"
      state               = "mi"
      locality            = "Westland"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:02:80:9d:c3:4a:10:a4:7e:8d:bb:fe:00:00:00:02:80:9d"
      )
}
