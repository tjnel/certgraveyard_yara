import "pe"

rule MAL_Compromised_Cert_RdViewer_Certum_758AF88B88D2116ABFA80F2351FD82F2 {
   meta:
      description         = "Detects RdViewer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-21"
      version             = "1.0"

      hash                = "fdc6ffb9ab42d717285e71dca3a5ad9798c385927ca5e59dc41c4caa4219ad23"
      malware             = "RdViewer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "王正福"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "75:8a:f8:8b:88:d2:11:6a:bf:a8:0f:23:51:fd:82:f2"
      cert_thumbprint     = "447154470ded347677bfa03280caab195eb1dcd0"
      cert_valid_from     = "2026-11-21"
      cert_valid_to       = "2027-11-21"

      country             = "CN"
      state               = "云南省"
      locality            = "大理白族自治州"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "75:8a:f8:8b:88:d2:11:6a:bf:a8:0f:23:51:fd:82:f2"
      )
}
