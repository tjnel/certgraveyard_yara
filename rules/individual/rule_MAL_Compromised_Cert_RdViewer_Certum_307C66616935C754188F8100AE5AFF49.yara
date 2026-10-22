import "pe"

rule MAL_Compromised_Cert_RdViewer_Certum_307C66616935C754188F8100AE5AFF49 {
   meta:
      description         = "Detects RdViewer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-18"
      version             = "1.0"

      hash                = "b9115303dd3567ac75104a5a3d2bc0ce4fd7d697ebf258e61283cdf708d50133"
      malware             = "RdViewer"
      malware_type        = "Remote access tool"
      malware_notes       = "https://rogueauthority.org/signed-disk-manager-installs-rdviewer-backdoor"

      signer              = "黄张兴"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "30:7c:66:61:69:35:c7:54:18:8f:81:00:ae:5a:ff:49"
      cert_thumbprint     = "0fa370c6efc1865dd3a2cc9e3089b969d30a15e4"
      cert_valid_from     = "2026-10-18"
      cert_valid_to       = "2027-10-18"

      country             = "CN"
      state               = "福建省"
      locality            = "福州市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "30:7c:66:61:69:35:c7:54:18:8f:81:00:ae:5a:ff:49"
      )
}
