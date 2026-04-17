import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Microsoft_33000056B4BBEA79F1DA04E1350000000056B4 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-14"
      version             = "1.0"

      hash                = "2393f751bf8a61d6c5145eb0d0e2e904797f633146479165170d7cfa3b15f63d"
      malware             = "NetSupport RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ANTHONY PERKINS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:56:b4:bb:ea:79:f1:da:04:e1:35:00:00:00:00:56:b4"
      cert_thumbprint     = "36FB05372C4865A733B6FAFE345DD585628DAE07"
      cert_valid_from     = "2026-04-14"
      cert_valid_to       = "2026-04-17"

      country             = "US"
      state               = "Alaska"
      locality            = "PALMER"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:56:b4:bb:ea:79:f1:da:04:e1:35:00:00:00:00:56:b4"
      )
}
