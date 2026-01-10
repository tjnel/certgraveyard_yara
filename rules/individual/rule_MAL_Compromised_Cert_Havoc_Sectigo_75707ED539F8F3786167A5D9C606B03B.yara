import "pe"

rule MAL_Compromised_Cert_Havoc_Sectigo_75707ED539F8F3786167A5D9C606B03B {
   meta:
      description         = "Detects Havoc with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-21"
      version             = "1.0"

      hash                = "c2b4214f65aaf845bb7ec37c7fe83270d5774ec3b1eafb47cc4b9f793be8c35f"
      malware             = "Havoc"
      malware_type        = "Remote access tool"
      malware_notes       = "This EXE was disguised as a PDF seemingly targeting Belguim and French organizations."

      signer              = "BAUCHET LILIAN"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "75:70:7e:d5:39:f8:f3:78:61:67:a5:d9:c6:06:b0:3b"
      cert_thumbprint     = "258B6E3D29ADCE07B7785B1DA03EC8B9076C0C6C"
      cert_valid_from     = "2025-10-21"
      cert_valid_to       = "2026-10-21"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "75:70:7e:d5:39:f8:f3:78:61:67:a5:d9:c6:06:b0:3b"
      )
}
