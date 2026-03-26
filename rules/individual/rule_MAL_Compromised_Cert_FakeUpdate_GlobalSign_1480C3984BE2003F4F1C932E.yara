import "pe"

rule MAL_Compromised_Cert_FakeUpdate_GlobalSign_1480C3984BE2003F4F1C932E {
   meta:
      description         = "Detects FakeUpdate with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-03"
      version             = "1.0"

      hash                = "073f3e7f0b4594cfbcf759bc7075219060cf91f2c237cc34bb52b79978d72632"
      malware             = "FakeUpdate"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CULTURE & EDUCATION INTERNATIONAL LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "14:80:c3:98:4b:e2:00:3f:4f:1c:93:2e"
      cert_thumbprint     = "1D0548C7C172AA20FE7755FEA7B96F193FAC30CC"
      cert_valid_from     = "2026-02-03"
      cert_valid_to       = "2027-02-04"

      country             = "GB"
      state               = "Greater London"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "14274607"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "14:80:c3:98:4b:e2:00:3f:4f:1c:93:2e"
      )
}
