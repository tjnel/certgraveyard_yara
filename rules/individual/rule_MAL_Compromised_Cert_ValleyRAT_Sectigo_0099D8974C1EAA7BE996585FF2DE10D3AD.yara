import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Sectigo_0099D8974C1EAA7BE996585FF2DE10D3AD {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-27"
      version             = "1.0"

      hash                = "e17d12a3cb758a7cd55d9e0305bc1471d30a7125cb14f3574d47f1bb91216fc4"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = "C2: 7799[.]5oo[.]im"

      signer              = "MiniTool Software Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:99:d8:97:4c:1e:aa:7b:e9:96:58:5f:f2:de:10:d3:ad"
      cert_thumbprint     = "AF86A6BF744DCD8EF77FF4A4C8BFCDB099323A51"
      cert_valid_from     = "2026-03-27"
      cert_valid_to       = "2027-03-26"

      country             = "HK"
      state               = "Hong Kong"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "66345010"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:99:d8:97:4c:1e:aa:7b:e9:96:58:5f:f2:de:10:d3:ad"
      )
}
