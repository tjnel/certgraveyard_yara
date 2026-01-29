import "pe"

rule MAL_Compromised_Cert_MarkiRAT_SSL_com_12CA4926152D33A0EEEB8E9C30A49A1D {
   meta:
      description         = "Detects MarkiRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-28"
      version             = "1.0"

      hash                = "a4f1b79e96a7d016de1991a64506792018de99eac5df00f7cabe26ef41b2bd81"
      malware             = "MarkiRAT"
      malware_type        = "Trojan"
      malware_notes       = "File uses same mutex and C2 behavior as previously reported by https://securelist.com/ferocious-kitten-6-years-of-covert-surveillance-in-iran/102806/"

      signer              = "Nikki Boy Semblante"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "12:ca:49:26:15:2d:33:a0:ee:eb:8e:9c:30:a4:9a:1d"
      cert_thumbprint     = "EAB8C45400DBCDB0B956DFF73984B8FC323E2013"
      cert_valid_from     = "2025-07-28"
      cert_valid_to       = "2026-07-28"

      country             = "PH"
      state               = "Leyte"
      locality            = "Ormoc City"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "12:ca:49:26:15:2d:33:a0:ee:eb:8e:9c:30:a4:9a:1d"
      )
}
