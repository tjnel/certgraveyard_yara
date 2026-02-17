import "pe"

rule MAL_Compromised_Cert_FakeCiscoVPN_Sectigo_00BBD8E8B439FE6DB51E2E4EC70504A439 {
   meta:
      description         = "Detects FakeCiscoVPN with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-23"
      version             = "1.0"

      hash                = "e357dd02c9d4b5769b40dc0bfa35ca561fc132b65720eb109d5b8817c285fb16"
      malware             = "FakeCiscoVPN"
      malware_type        = "Unknown"
      malware_notes       = "Trojanized Cisco VPN installer smuggling credentials used to 5.149.253.235/income_shit"

      signer              = "Unbounded (Xiamen) Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:bb:d8:e8:b4:39:fe:6d:b5:1e:2e:4e:c7:05:04:a4:39"
      cert_thumbprint     = "4BBC1280E449B3DA961B91B1D871F27ADE72D860"
      cert_valid_from     = "2026-01-23"
      cert_valid_to       = "2027-01-23"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:bb:d8:e8:b4:39:fe:6d:b5:1e:2e:4e:c7:05:04:a4:39"
      )
}
