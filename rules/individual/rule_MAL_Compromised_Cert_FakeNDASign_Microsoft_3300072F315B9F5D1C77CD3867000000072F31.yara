import "pe"

rule MAL_Compromised_Cert_FakeNDASign_Microsoft_3300072F315B9F5D1C77CD3867000000072F31 {
   meta:
      description         = "Detects FakeNDASign with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-02"
      version             = "1.0"

      hash                = "eaf020843f72140f722875135d2ce63c723afb22c7dfc8e04794182d7f398222"
      malware             = "FakeNDASign"
      malware_type        = "Unknown"
      malware_notes       = "Malware campaign targeting job-seekers with fake landing ndavia[.]com"

      signer              = "Brice Carpenter"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:2f:31:5b:9f:5d:1c:77:cd:38:67:00:00:00:07:2f:31"
      cert_thumbprint     = "B3C8F3D5E37B3807A5C21A5A8E0F5F28D069A362"
      cert_valid_from     = "2026-03-02"
      cert_valid_to       = "2026-03-05"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:2f:31:5b:9f:5d:1c:77:cd:38:67:00:00:00:07:2f:31"
      )
}
