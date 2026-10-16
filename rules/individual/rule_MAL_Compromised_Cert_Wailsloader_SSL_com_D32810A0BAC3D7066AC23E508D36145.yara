import "pe"

rule MAL_Compromised_Cert_Wailsloader_SSL_com_D32810A0BAC3D7066AC23E508D36145 {
   meta:
      description         = "Detects Wailsloader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-27"
      version             = "1.0"

      hash                = "0bcf272d8f22fa30d327d7c0233b7eae7d50df1ebd95472aae59aef19c8e23bf"
      malware             = "Wailsloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KIROPRAKTOR GUSTAV SELLERGREN ANS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "d3:28:10:a0:ba:c3:d7:06:6a:c2:3e:50:8d:36:14:5"
      cert_thumbprint     = "8ec984534c70415202b9cf60bc1793f0c9260e53"
      cert_valid_from     = "2026-08-27"
      cert_valid_to       = "2027-08-27"

      country             = "NO"
      state               = "Vestfold"
      locality            = "Tønsberg"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "d3:28:10:a0:ba:c3:d7:06:6a:c2:3e:50:8d:36:14:5"
      )
}
