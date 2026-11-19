import "pe"

rule MAL_Compromised_Cert_UpdateLogger_Certum_588830EC377C2AA07B017B09CA12F2EC {
   meta:
      description         = "Detects UpdateLogger with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-21"
      version             = "1.0"

      hash                = "a958ceb59c097fa8bc7c667abcdfc320e94062b8f7cb71e1d92a8dfce0d74850"
      malware             = "UpdateLogger"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "021 d.o.o."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "58:88:30:ec:37:7c:2a:a0:7b:01:7b:09:ca:12:f2:ec"
      cert_thumbprint     = "172258d081145a93b16d4f7d7e2d9a13a2b0dd8f"
      cert_valid_from     = "2026-10-21"
      cert_valid_to       = "2027-10-21"

      country             = "HR"
      state               = "Splitsko-dalmatinska"
      locality            = "Split"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "58:88:30:ec:37:7c:2a:a0:7b:01:7b:09:ca:12:f2:ec"
      )
}
