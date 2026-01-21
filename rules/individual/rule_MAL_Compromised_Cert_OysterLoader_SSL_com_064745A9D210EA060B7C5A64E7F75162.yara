import "pe"

rule MAL_Compromised_Cert_OysterLoader_SSL_com_064745A9D210EA060B7C5A64E7F75162 {
   meta:
      description         = "Detects OysterLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-28"
      version             = "1.0"

      hash                = "33448e03ab7973452032086db5dcb22e7526fe5b46df093902986664072bb12a"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was part of an ongoing campaign and was disguised as an AI application: AIVpro_alpha.exe. The malware created a scheduled task for persistence. If unmitigated, provides remote access to ransomware actors."

      signer              = "PANGEA CIVIL ENGINEERS SRL"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "06:47:45:a9:d2:10:ea:06:0b:7c:5a:64:e7:f7:51:62"
      cert_thumbprint     = "D2F530D7A6A152E3198F6B1326F8FC54098C09D2"
      cert_valid_from     = "2025-08-28"
      cert_valid_to       = "2026-08-28"

      country             = "RO"
      state               = "Ilfov County"
      locality            = "Popeşti-Leordeni"
      email               = "???"
      rdn_serial_number   = "J23 30 2013"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "06:47:45:a9:d2:10:ea:06:0b:7c:5a:64:e7:f7:51:62"
      )
}
