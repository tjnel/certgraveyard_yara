import "pe"

rule MAL_Compromised_Cert_FakeRMM_GlobalSign_3AB8F2A0FD69A9852BB9B04C {
   meta:
      description         = "Detects FakeRMM with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-23"
      version             = "1.0"

      hash                = "d7927be965adc51a33efc4bea23f64f6aed37d1e18b5693b6bd41670f5f1adb7"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "C2: mini-rrm[.]io"

      signer              = "HORECA tech d.o.o."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3a:b8:f2:a0:fd:69:a9:85:2b:b9:b0:4c"
      cert_thumbprint     = "E1C031ADD08CA22079259C6CF2DB17FA7D43FA70"
      cert_valid_from     = "2026-04-23"
      cert_valid_to       = "2027-04-24"

      country             = "HR"
      state               = "Grad Zagreb"
      locality            = "Zagreb"
      email               = "amar@eugostitelj.com"
      rdn_serial_number   = "081408314"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3a:b8:f2:a0:fd:69:a9:85:2b:b9:b0:4c"
      )
}
