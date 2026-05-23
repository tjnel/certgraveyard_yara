import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000820B3CD4E8E8E726F0C4C0000000820B3 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-02"
      version             = "1.0"

      hash                = "c9e0e6985dca3a179c9bdea4e7b38f7dc57fe00ecedc2fd634256fc53bf2de2d"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = "Was disguised as ChatGPT desktop installer. Reported as deploying NetSupport RAT"

      signer              = "NETWORK CONNECTIONS PROJECT SRL"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:20:b3:cd:4e:8e:8e:72:6f:0c:4c:00:00:00:08:20:b3"
      cert_thumbprint     = "CB1FC111EDBF6D56C6F2DFB959039A1A2A5F80FF"
      cert_valid_from     = "2026-03-02"
      cert_valid_to       = "2026-03-05"

      country             = "RO"
      state               = "Arges"
      locality            = "Pitesti"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:20:b3:cd:4e:8e:8e:72:6f:0c:4c:00:00:00:08:20:b3"
      )
}
