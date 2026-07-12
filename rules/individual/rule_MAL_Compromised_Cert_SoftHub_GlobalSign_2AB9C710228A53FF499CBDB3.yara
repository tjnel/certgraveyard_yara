import "pe"

rule MAL_Compromised_Cert_SoftHub_GlobalSign_2AB9C710228A53FF499CBDB3 {
   meta:
      description         = "Detects SoftHub with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-19"
      version             = "1.0"

      hash                = "ee18394f83bf2d83c44ae79bc1ef297ab172de6461b6ab2dc364eae096f75181"
      malware             = "SoftHub"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Osh Spetsstroy LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2a:b9:c7:10:22:8a:53:ff:49:9c:bd:b3"
      cert_thumbprint     = "CA2165E0F8DB97900D679B6D821CBC3D87D4AC32"
      cert_valid_from     = "2026-06-19"
      cert_valid_to       = "2027-06-20"

      country             = "KG"
      state               = "Osh"
      locality            = "Kara-Suu"
      email               = "Oshstroy@protonmail.com"
      rdn_serial_number   = "163181-3306-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2a:b9:c7:10:22:8a:53:ff:49:9c:bd:b3"
      )
}
