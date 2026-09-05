import "pe"

rule MAL_Compromised_Cert_Certificate_warming_GlobalSign_D17C66A5507ABFAA3B70C38 {
   meta:
      description         = "Detects Certificate warming with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-19"
      version             = "1.0"

      hash                = "56b6a194031b8403b7ff166187783d51acc7fe66cf930d9a0777ab1d9bb592c3"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MINERALS GROUP AS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "d1:7c:66:a5:50:7a:bf:aa:3b:70:c3:8"
      cert_thumbprint     = "8c33f0d44f550406927d9b6c805d930a36d3a5f5"
      cert_valid_from     = "2026-08-19"
      cert_valid_to       = "2027-06-25"

      country             = "NO"
      state               = "Rogaland"
      locality            = "Stavanger"
      email               = "mads.grinrod@mineralsgropup.no"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "d1:7c:66:a5:50:7a:bf:aa:3b:70:c3:8"
      )
}
