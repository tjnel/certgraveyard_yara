import "pe"

rule MAL_Compromised_Cert_FakeRMM_SSL_com_C4645F0F1D8CC36C7E16E9207FC05E4 {
   meta:
      description         = "Detects FakeRMM with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-07"
      version             = "1.0"

      hash                = "d183c675620a9388e2906a81249c502898e5c7cab370265ac39b177aed49ab21"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PRXY TECHNOLOGIES LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "c4:64:5f:0f:1d:8c:c3:6c:7e:16:e9:20:7f:c0:5e:4"
      cert_thumbprint     = "6b96647d5b31961ef8119c3ca9b98dbd2fdac58f"
      cert_valid_from     = "2026-09-07"
      cert_valid_to       = "2027-09-07"

      country             = "US"
      state               = "Illinois"
      locality            = "Decatur"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "c4:64:5f:0f:1d:8c:c3:6c:7e:16:e9:20:7f:c0:5e:4"
      )
}
