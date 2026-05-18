import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000AE8CFBA7A14E8C43258A00000000AE8C {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-02"
      version             = "1.0"

      hash                = "d9b96bcae643fcaef0e4f772b0358542064aa9b2e32496ba632f738fc09d16a2"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Avery Benavidez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:ae:8c:fb:a7:a1:4e:8c:43:25:8a:00:00:00:00:ae:8c"
      cert_thumbprint     = "F0DBB0234466C1E68C6A71061B95C51EA61B42B8"
      cert_valid_from     = "2026-05-02"
      cert_valid_to       = "2026-05-05"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:ae:8c:fb:a7:a1:4e:8c:43:25:8a:00:00:00:00:ae:8c"
      )
}
