import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_1F614124E11DE641C7D2C7D0A3C6100C {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-09"
      version             = "1.0"

      hash                = "1c82635c29f40e971971e150ebee6f36dabdd2a156f51214f20425315abb413f"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = "C2: 103.118.243.73"

      signer              = "成都拾屋理铭酒店管理有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "1f:61:41:24:e1:1d:e6:41:c7:d2:c7:d0:a3:c6:10:0c"
      cert_thumbprint     = "A962F3592C72311BC617453102AA8AE2294BEA11"
      cert_valid_from     = "2026-02-09"
      cert_valid_to       = "2027-02-09"

      country             = "CN"
      state               = "四川"
      locality            = "成都"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "1f:61:41:24:e1:1d:e6:41:c7:d2:c7:d0:a3:c6:10:0c"
      )
}
