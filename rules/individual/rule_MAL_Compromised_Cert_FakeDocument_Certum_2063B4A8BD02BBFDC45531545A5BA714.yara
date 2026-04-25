import "pe"

rule MAL_Compromised_Cert_FakeDocument_Certum_2063B4A8BD02BBFDC45531545A5BA714 {
   meta:
      description         = "Detects FakeDocument with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-30"
      version             = "1.0"

      hash                = "8048014d326e4cadd657ad9a58fa470969e27783a668d1133a7d1c77b80dae11"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = "Fake invoices targeting Italian users"

      signer              = "Zunhua Shengzhi Cloud Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "20:63:b4:a8:bd:02:bb:fd:c4:55:31:54:5a:5b:a7:14"
      cert_thumbprint     = "B79BF05C200C3074539A4F85D07E26923F756B79"
      cert_valid_from     = "2026-03-30"
      cert_valid_to       = "2027-03-30"

      country             = "CN"
      state               = "河北省"
      locality            = "唐山市"
      email               = "???"
      rdn_serial_number   = "91130281MAET3CD19W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "20:63:b4:a8:bd:02:bb:fd:c4:55:31:54:5a:5b:a7:14"
      )
}
