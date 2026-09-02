import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_1B1F4B77CD1513FAFBF557FD5FF4897C {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-16"
      version             = "1.0"

      hash                = "02d3ad426de6498186e159a577c771f8fcb61604cf62a378deef982dead505d4"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Shaanxi Chifeng Pinhe Agricultural Technology Co., Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "1b:1f:4b:77:cd:15:13:fa:fb:f5:57:fd:5f:f4:89:7c"
      cert_thumbprint     = "1820b749b89bd201d3bdddbb802973a43876e44e"
      cert_valid_from     = "2026-07-16"
      cert_valid_to       = "2027-07-16"

      country             = "CN"
      state               = "Shaanxi"
      locality            = "Xianyang"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "1b:1f:4b:77:cd:15:13:fa:fb:f5:57:fd:5f:f4:89:7c"
      )
}
