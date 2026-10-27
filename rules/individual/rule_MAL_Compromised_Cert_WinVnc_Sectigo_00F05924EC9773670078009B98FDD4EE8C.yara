import "pe"

rule MAL_Compromised_Cert_WinVnc_Sectigo_00F05924EC9773670078009B98FDD4EE8C {
   meta:
      description         = "Detects WinVnc with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-16"
      version             = "1.0"

      hash                = "57234adeec71c84e6dc9d353f4a250d3c8da2e9a05e6f9090045b53c50d01ad6"
      malware             = "WinVnc"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ARONEL LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:f0:59:24:ec:97:73:67:00:78:00:9b:98:fd:d4:ee:8c"
      cert_thumbprint     = "D57A6E28388CEF0B66D3B30CEBEC3D599122A624"
      cert_valid_from     = "2026-03-16"
      cert_valid_to       = "2027-03-09"

      country             = "GB"
      state               = "England"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:f0:59:24:ec:97:73:67:00:78:00:9b:98:fd:d4:ee:8c"
      )
}
