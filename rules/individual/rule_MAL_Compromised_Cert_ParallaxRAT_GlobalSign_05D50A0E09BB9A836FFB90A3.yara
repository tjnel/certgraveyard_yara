import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_GlobalSign_05D50A0E09BB9A836FFB90A3 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-02-03"
      version             = "1.0"

      hash                = "377ecfd2413aa044082c4f89e7c50baaeac0acbae8d7f5ada32ad915ad905557"
      malware             = "ParallaxRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Toliz Info Tech Solutions INC."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "05:d5:0a:0e:09:bb:9a:83:6f:fb:90:a3"
      cert_thumbprint     = "975AFE2CC21AE05FF4EE5A7271E125D13BF6163C"
      cert_valid_from     = "2022-02-03"
      cert_valid_to       = "2023-02-04"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ajax"
      email               = "Abigail.D@solbertec.com"
      rdn_serial_number   = "1005311-2"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "05:d5:0a:0e:09:bb:9a:83:6f:fb:90:a3"
      )
}
