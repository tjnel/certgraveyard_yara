import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_00995B7EFE49137D33BD8C10 {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-11"
      version             = "1.0"

      hash                = "e4ccb3da7bfdf816ae16790859255647322655502ac4e18e1e52ba5967230be6"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: dallasgeneratorshop[.]com"

      signer              = "CONG TY TNHH TIEN PHONG THAI BINH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "00:99:5b:7e:fe:49:13:7d:33:bd:8c:10"
      cert_thumbprint     = "E60DAA112E0E49C117CEEEDC72412FF656D4D093"
      cert_valid_from     = "2026-02-11"
      cert_valid_to       = "2027-02-12"

      country             = "VN"
      state               = "Hung Yen"
      locality            = "Hung Yen"
      email               = "account2.hdp@pioneer-v.com"
      rdn_serial_number   = "1001111635"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "00:99:5b:7e:fe:49:13:7d:33:bd:8c:10"
      )
}
