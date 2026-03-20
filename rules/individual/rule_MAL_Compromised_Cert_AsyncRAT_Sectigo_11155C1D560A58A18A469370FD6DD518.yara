import "pe"

rule MAL_Compromised_Cert_AsyncRAT_Sectigo_11155C1D560A58A18A469370FD6DD518 {
   meta:
      description         = "Detects AsyncRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-27"
      version             = "1.0"

      hash                = "603e3c39f005b3d1b924cee22074cb5e93c5330795cca92da39c5f8d7063879f"
      malware             = "AsyncRAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Wuhan Jianzhuohong Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "11:15:5c:1d:56:0a:58:a1:8a:46:93:70:fd:6d:d5:18"
      cert_thumbprint     = "766E5978509A61E4BCFF199AF186151283AF16FF"
      cert_valid_from     = "2026-01-27"
      cert_valid_to       = "2027-01-27"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "11:15:5c:1d:56:0a:58:a1:8a:46:93:70:fd:6d:d5:18"
      )
}
