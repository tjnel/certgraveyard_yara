import "pe"

rule MAL_Compromised_Cert_RUS_53_GlobalSign_10C33F009B54F66A849B4C90 {
   meta:
      description         = "Detects RUS-53 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "1d2c7d7a9410bf6c582cb9036c98562b1b79db9b47e73d902da5675e4527319f"
      malware             = "RUS-53"
      malware_type        = "Remote access tool"
      malware_notes       = "Malware uses fake PDF icon, behavior and file composition is consistent with a previously seen malware: https://github.com/Squiblydoo/Remnux_Reports/blob/main/Reports%20by%20hash/1d2c7d7a9410bf6c582cb9036c98562b1b79db9b47e73d902da5675e4527319f_WH_1E_1/analysis_report.md"

      signer              = "威海市明骏信息科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "10:c3:3f:00:9b:54:f6:6a:84:9b:4c:90"
      cert_thumbprint     = "94B9CCD1D9A13DA7F19018E51B21628FCE6A59A7"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-04-09"

      country             = "CN"
      state               = "山东"
      locality            = "威海"
      email               = "???"
      rdn_serial_number   = "91371000MA3WAC7627"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "10:c3:3f:00:9b:54:f6:6a:84:9b:4c:90"
      )
}
