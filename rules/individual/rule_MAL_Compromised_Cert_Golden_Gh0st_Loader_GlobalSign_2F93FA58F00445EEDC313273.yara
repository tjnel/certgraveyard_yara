import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_GlobalSign_2F93FA58F00445EEDC313273 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-22"
      version             = "1.0"

      hash                = "16e01dd4c60462c0a870bf55ec987514e122f27b306858e73f71a8ca4b896423"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Chengdu Nuoxin Times Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2f:93:fa:58:f0:04:45:ee:dc:31:32:73"
      cert_thumbprint     = "3CF1146EDC6B0C3595D5C8C015BF52E77BA1C74C"
      cert_valid_from     = "2025-04-22"
      cert_valid_to       = "2026-08-14"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510100MA65214R21"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2f:93:fa:58:f0:04:45:ee:dc:31:32:73"
      )
}
